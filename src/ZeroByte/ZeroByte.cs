// ZeroByte SDK for .NET (Windows, and anywhere .NET runs ChaCha20-Poly1305):
// Relay Protocol v1, https://docs.zerobyte.cloud/protocol/

using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroByte;

/// <summary>Which side of a link wrote an envelope.</summary>
public enum Direction : byte
{
    P2C = 1,
    C2P = 2,
}

public static class DirectionExtensions
{
    public static Direction Reversed(this Direction d) => d == Direction.P2C ? Direction.C2P : Direction.P2C;

    internal static string Path(this Direction d) => d == Direction.P2C ? "p2c" : "c2p";
}

/// <summary>Envelope errors. <see cref="Code"/> is the same string in every ZeroByte SDK.</summary>
public sealed class ZeroByteException(string code) : Exception(code)
{
    public string Code { get; } = code;
}

/// <summary>
/// Relay errors. <see cref="Last"/> is the relay's highest sequence on a 409;
/// <see cref="RetryAfter"/> how long to wait on a 429 (<c>rate_limited</c>).
/// </summary>
public sealed class RelayException(string code, int status, ulong? last = null, TimeSpan? retryAfter = null)
    : Exception($"{code} ({status})")
{
    public string Code { get; } = code;
    public int Status { get; } = status;
    public ulong? Last { get; } = last;
    public TimeSpan? RetryAfter { get; } = retryAfter;
}

/// <summary>Whether a write should wake the reader with a push (the relay's push extension).</summary>
public enum Notify
{
    None,
    /// <summary>A visible notification the app replaces with the decrypted message.</summary>
    Alert,
    /// <summary>A background push.</summary>
    Silent,
}

/// <summary>
/// Where the relay sends pushes for one direction. The relay knows push
/// services as separate modules; <see cref="Fields"/> are the service's own.
/// For APNs use the <c>ZeroByte.Apns</c> package.
/// </summary>
public sealed record PushRegistration(
    string Service, IReadOnlyDictionary<string, string> Fields, string Tag, string? Alert = null)
{
    /// <summary>A fresh random tag: 22 base64url characters.</summary>
    public static string RandomTag() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>The body of <c>PUT …/push</c>.</summary>
    public string ToJson()
    {
        var body = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (k, v) in Fields) body[k] = v;
        body["service"] = Service;
        body["tag"] = Tag;
        if (Alert is not null) body["alert"] = Alert;
        return JsonSerializer.Serialize(body);
    }
}

/// <summary>One STUN or TURN server, in the shape of WebRTC's <c>RTCIceServer</c>.</summary>
public sealed record IceServer(
    [property: JsonPropertyName("urls")] IReadOnlyList<string> Urls,
    [property: JsonPropertyName("username")] string? Username = null,
    [property: JsonPropertyName("credential")] string? Credential = null);

/// <summary>STUN/TURN servers and how many seconds their credentials last.</summary>
public sealed record IceConfiguration(
    [property: JsonPropertyName("iceServers")] IReadOnlyList<IceServer> IceServers,
    [property: JsonPropertyName("ttl")] int Ttl);

/// <summary>
/// Everything one paired link needs, derived from the 32-byte link key both
/// devices agreed when they paired, salted with 16 bytes naming the link.
/// </summary>
public sealed class Credentials
{
    // The labels are part of the wire format: changing one is a new protocol version.
    private const string MailboxLabel = "zerobyte-relay-mailbox-v1";
    private const string TokenLabel = "zerobyte-relay-token-v1";
    private const string P2CLabel = "zerobyte-relay-p2c-v1";
    private const string C2PLabel = "zerobyte-relay-c2p-v1";
    private const string SignalP2CLabel = "zerobyte-signal-p2c-v1";
    private const string SignalC2PLabel = "zerobyte-signal-c2p-v1";

    private readonly byte[] _p2c;
    private readonly byte[] _c2p;
    private readonly byte[] _signalP2C;
    private readonly byte[] _signalC2P;

    public byte[] MailboxID { get; }
    public byte[] AccessToken { get; }

    public Credentials(ReadOnlySpan<byte> linkKey, ReadOnlySpan<byte> linkID)
    {
        if (linkKey.Length != 32 || linkID.Length != 16) throw new ZeroByteException("invalid_key");
        MailboxID = Derive(linkKey, linkID, MailboxLabel, 16);
        AccessToken = Derive(linkKey, linkID, TokenLabel, 32);
        _p2c = Derive(linkKey, linkID, P2CLabel, 32);
        _c2p = Derive(linkKey, linkID, C2PLabel, 32);
        _signalP2C = Derive(linkKey, linkID, SignalP2CLabel, 32);
        _signalC2P = Derive(linkKey, linkID, SignalC2PLabel, 32);
    }

    /// <summary>A UUID link id, in RFC 4122 byte order (not <see cref="Guid.ToByteArray()"/>'s).</summary>
    public Credentials(ReadOnlySpan<byte> linkKey, Guid linkID) : this(linkKey, linkID.ToByteArray(bigEndian: true)) { }

    private static byte[] Derive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, string info, int length)
    {
        var output = new byte[length];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt, Encoding.UTF8.GetBytes(info));
        return output;
    }

    /// <summary>The mailbox's name in URLs: 32 lowercase hex characters.</summary>
    public string MailboxName => Convert.ToHexStringLower(MailboxID);

    /// <summary>The bearer token: base64url without padding.</summary>
    public string BearerToken =>
        Convert.ToBase64String(AccessToken).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>What the relay stores instead of the token: SHA-256, lowercase hex.</summary>
    public string TokenDigest => Convert.ToHexStringLower(SHA256.HashData(AccessToken));

    internal byte[] Key(Direction d) => d == Direction.P2C ? _p2c : _c2p;

    /// <summary>The key for signal frames in one direction, separate from the envelope keys.</summary>
    public byte[] SignalKey(Direction d) => (byte[])(d == Direction.P2C ? _signalP2C : _signalC2P).Clone();
}

/// <summary>An opened message.</summary>
public readonly record struct Opened(ulong Sequence, byte[] Plaintext);

/// <summary>
/// <c>version(1) ‖ direction(1) ‖ sequence(UInt64 BE) ‖ nonce(12) ‖ ciphertext ‖ tag(16)</c>,
/// sealed with ChaCha20-Poly1305 over AAD = header ‖ mailboxID.
/// </summary>
public static class Envelope
{
    public const byte Version = 1;
    public const int HeaderLength = 10;
    public const int NonceLength = 12;
    public const int TagLength = 16;
    public const int Overhead = HeaderLength + NonceLength + TagLength;
    public const int MaxPlaintextBytes = 1_048_576;
    public const int MaxEnvelopeBytes = MaxPlaintextBytes + Overhead;

    /// <summary>
    /// False where the platform has no ChaCha20-Poly1305 (Windows before 10
    /// 20H2, some Linux builds). Every call below throws there.
    /// </summary>
    public static bool IsSupported => ChaCha20Poly1305.IsSupported;

    /// <summary>The clear header, without opening.</summary>
    public static (Direction Direction, ulong Sequence) ReadHeader(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < Overhead) throw new ZeroByteException("malformed");
        if (envelope[0] != Version) throw new ZeroByteException("unsupported_version");
        if (envelope[1] is not (1 or 2)) throw new ZeroByteException("malformed");
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(envelope[2..]);
        if (sequence == 0) throw new ZeroByteException("malformed");
        return ((Direction)envelope[1], sequence);
    }

    /// <summary>Seals a message. <paramref name="nonce"/> is for known-answer tests only.</summary>
    public static byte[] Seal(
        ReadOnlySpan<byte> plaintext, Direction direction, ulong sequence, Credentials credentials,
        byte[]? nonce = null)
    {
        if (plaintext.Length > MaxPlaintextBytes) throw new ZeroByteException("too_large");
        return SealWith(credentials.Key(direction), plaintext, direction, sequence, credentials, nonce);
    }

    internal static byte[] SealWith(
        byte[] key, ReadOnlySpan<byte> plaintext, Direction direction, ulong sequence, Credentials credentials,
        byte[]? nonce)
    {
        if (sequence == 0) throw new ZeroByteException("malformed");
        var output = new byte[Overhead + plaintext.Length];
        var span = output.AsSpan();
        span[0] = Version;
        span[1] = (byte)direction;
        BinaryPrimitives.WriteUInt64BigEndian(span[2..], sequence);
        var n = span.Slice(HeaderLength, NonceLength);
        if (nonce is null) RandomNumberGenerator.Fill(n);
        else nonce.CopyTo(n);
        using var aead = new ChaCha20Poly1305(key);
        aead.Encrypt(
            n, plaintext,
            span.Slice(HeaderLength + NonceLength, plaintext.Length),
            span[^TagLength..],
            Aad(span[..HeaderLength], credentials));
        return output;
    }

    /// <summary>
    /// Opens an envelope the other side wrote. <paramref name="after"/> is the
    /// highest sequence already accepted, or null.
    /// </summary>
    public static Opened Open(ReadOnlySpan<byte> envelope, Direction direction, ulong? after, Credentials credentials)
    {
        if (envelope.Length > MaxEnvelopeBytes) throw new ZeroByteException("too_large");
        var (written, sequence) = ReadHeader(envelope);
        if (written != direction) throw new ZeroByteException("wrong_direction");
        if (after is { } a && sequence <= a) throw new ZeroByteException("replayed");
        return OpenWith(credentials.Key(direction), envelope, sequence, credentials);
    }

    internal static Opened OpenWith(byte[] key, ReadOnlySpan<byte> envelope, ulong sequence, Credentials credentials)
    {
        var body = envelope[(HeaderLength + NonceLength)..^TagLength];
        var plaintext = new byte[body.Length];
        try
        {
            using var aead = new ChaCha20Poly1305(key);
            aead.Decrypt(
                envelope.Slice(HeaderLength, NonceLength), body, envelope[^TagLength..], plaintext,
                Aad(envelope[..HeaderLength], credentials));
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new ZeroByteException("authentication_failed");
        }
        return new Opened(sequence, plaintext);
    }

    private static byte[] Aad(ReadOnlySpan<byte> header, Credentials credentials) =>
        [.. header, .. credentials.MailboxID];
}

/// <summary>
/// Signal frames (the relay's signal extension): the envelope layout under the
/// signal keys, with a counter (milliseconds since 1970, always increasing) in
/// place of the sequence.
/// </summary>
public static class SignalFrame
{
    public const int MaxFrameBytes = 65_536;
    public const int MaxPlaintextBytes = MaxFrameBytes - Envelope.Overhead;
    /// <summary>How far a frame's counter may be from the receiver's clock.</summary>
    public const ulong WindowMilliseconds = 5 * 60 * 1000;

    /// <summary>Seals a frame. <paramref name="nonce"/> is for known-answer tests only.</summary>
    public static byte[] Seal(
        ReadOnlySpan<byte> plaintext, Direction direction, ulong counter, Credentials credentials,
        byte[]? nonce = null)
    {
        if (plaintext.Length > MaxPlaintextBytes) throw new ZeroByteException("too_large");
        return Envelope.SealWith(credentials.SignalKey(direction), plaintext, direction, counter, credentials, nonce);
    }

    /// <summary>
    /// Opens a frame the other side sent. Refuses one at or below <paramref name="after"/>
    /// or more than five minutes from <paramref name="now"/> (milliseconds since 1970).
    /// </summary>
    public static Opened Open(
        ReadOnlySpan<byte> frame, Direction direction, ulong? after, ulong now, Credentials credentials)
    {
        if (frame.Length > MaxFrameBytes) throw new ZeroByteException("too_large");
        var (written, counter) = Envelope.ReadHeader(frame);
        if (written != direction) throw new ZeroByteException("wrong_direction");
        if (after is { } a && counter <= a) throw new ZeroByteException("replayed");
        var distance = counter > now ? counter - now : now - counter;
        if (distance > WindowMilliseconds) throw new ZeroByteException("replayed");
        return Envelope.OpenWith(credentials.SignalKey(direction), frame, counter, credentials);
    }

    internal static ulong Now() => (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

/// <summary>A fetch body: <c>count(UInt32 BE)</c>, then <c>length(UInt32 BE) ‖ bytes</c> per envelope.</summary>
public static class Wire
{
    public const int MaximumCount = 64;

    public static byte[] Join(IReadOnlyList<byte[]> envelopes)
    {
        var output = new byte[4 + envelopes.Sum(e => 4 + e.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(output, (uint)envelopes.Count);
        var offset = 4;
        foreach (var e in envelopes)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), (uint)e.Length);
            e.CopyTo(output, offset + 4);
            offset += 4 + e.Length;
        }
        return output;
    }

    public static List<byte[]> Split(ReadOnlySpan<byte> body)
    {
        static RelayException Bad() => new("malformed_response", 200);
        if (body.Length < 4) throw Bad();
        var count = BinaryPrimitives.ReadUInt32BigEndian(body);
        if (count > MaximumCount) throw Bad();
        var output = new List<byte[]>((int)count);
        var offset = 4;
        for (var i = 0; i < count; i++)
        {
            if (body.Length - offset < 4) throw Bad();
            var length = BinaryPrimitives.ReadUInt32BigEndian(body[offset..]);
            offset += 4;
            if (length > Envelope.MaxEnvelopeBytes || length > body.Length - offset) throw Bad();
            output.Add(body.Slice(offset, (int)length).ToArray());
            offset += (int)length;
        }
        if (offset != body.Length) throw Bad();
        return output;
    }
}

/// <summary>One page of a fetch.</summary>
public sealed record Page(IReadOnlyList<byte[]> Envelopes, bool More);

/// <summary>What a <see cref="Link"/> needs from a relay.</summary>
public interface IRelayTransport
{
    Task ClaimAsync(CancellationToken ct = default);
    Task PutAsync(byte[] envelope, Direction direction, ulong sequence, CancellationToken ct = default);

    /// <summary>Stores one envelope and asks the relay to wake the reader. Without push, a plain put.</summary>
    Task PutAsync(byte[] envelope, Direction direction, ulong sequence, Notify notify, CancellationToken ct = default) =>
        PutAsync(envelope, direction, sequence, ct);

    Task<Page> FetchAsync(Direction direction, ulong? after, CancellationToken ct = default);
    Task<ulong?> LastSequenceAsync(Direction direction, CancellationToken ct = default);
    Task PruneAsync(Direction direction, ulong through, CancellationToken ct = default);
    Task EraseAsync(CancellationToken ct = default);
}

/// <summary>The HTTPS side of the protocol.</summary>
public sealed class Relay : IRelayTransport
{
    /// <summary>How often watch and signal sockets send <c>ping</c>.</summary>
    public static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(30);

    private readonly Credentials _credentials;
    private readonly HttpClient _http;

    internal Credentials Credentials => _credentials;

    public Uri Mailbox { get; }

    public Relay(string appID, Credentials credentials, Uri @base, HttpClient? http = null)
    {
        ArgumentNullException.ThrowIfNull(@base);
        _credentials = credentials;
        _http = http ?? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });
        Mailbox = new Uri(@base, $"{appID}/mailbox/{credentials.MailboxName}");
    }

    public async Task ClaimAsync(CancellationToken ct = default)
    {
        var json = $$"""{"tokenDigest":"{{_credentials.TokenDigest}}"}""";
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        (await SendAsync(HttpMethod.Put, "", content, ct)).Dispose();
    }

    public Task PutAsync(byte[] envelope, Direction direction, ulong sequence, CancellationToken ct = default) =>
        PutAsync(envelope, direction, sequence, Notify.None, ct);

    public async Task PutAsync(
        byte[] envelope, Direction direction, ulong sequence, Notify notify, CancellationToken ct = default)
    {
        using var content = new ByteArrayContent(envelope);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var header = notify switch { Notify.Alert => "alert", Notify.Silent => "silent", _ => null };
        (await SendAsync(HttpMethod.Put, $"/{direction.Path()}/{sequence}", content, ct, header)).Dispose();
    }

    /// <summary>
    /// Asks the relay to wake this device when the other side writes to
    /// <paramref name="direction"/> with a notify. Register on the direction you read.
    /// </summary>
    public async Task RegisterPushAsync(PushRegistration registration, Direction direction, CancellationToken ct = default)
    {
        using var content = new StringContent(registration.ToJson(), Encoding.UTF8, "application/json");
        (await SendAsync(HttpMethod.Put, $"/{direction.Path()}/push", content, ct)).Dispose();
    }

    public async Task UnregisterPushAsync(Direction direction, CancellationToken ct = default) =>
        (await SendAsync(HttpMethod.Delete, $"/{direction.Path()}/push", null, ct)).Dispose();

    /// <summary>STUN/TURN servers for a direct connection (the relay's ice extension).</summary>
    public async Task<IceConfiguration> IceServersAsync(CancellationToken ct = default)
    {
        using var response = await SendAsync(HttpMethod.Get, "/ice", null, ct);
        try
        {
            var value = await JsonSerializer.DeserializeAsync<IceConfiguration>(
                await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            return value?.IceServers is not null ? value : throw new JsonException();
        }
        catch (JsonException)
        {
            throw new RelayException("malformed_response", (int)response.StatusCode);
        }
    }

    /// <summary>A rendezvous with the other device. See <see cref="SignalChannel"/>.</summary>
    public SignalChannel Signal(Direction sends) => new(this, sends);

    internal async Task<ClientWebSocket> ConnectAsync(string path, CancellationToken ct)
    {
        var builder = new UriBuilder(new Uri($"{Mailbox}{path}"));
        builder.Scheme = builder.Scheme == "http" ? "ws" : "wss";
        var socket = new ClientWebSocket();
        socket.Options.AddSubProtocol("zerobyte.v1");
        socket.Options.SetRequestHeader("Authorization", $"Bearer {_credentials.BearerToken}");
        socket.Options.KeepAliveInterval = TimeSpan.Zero;
        try
        {
            await socket.ConnectAsync(builder.Uri, ct);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
        return socket;
    }

    /// <summary>Sends <c>ping</c> now and every 30 seconds, so the relay knows this side is awake.</summary>
    internal static async Task KeepAliveAsync(ClientWebSocket socket, SemaphoreSlim sending, CancellationToken ct)
    {
        var ping = Encoding.ASCII.GetBytes("ping");
        try
        {
            while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                await sending.WaitAsync(ct);
                try { await socket.SendAsync(ping, WebSocketMessageType.Text, true, ct); }
                finally { sending.Release(); }
                await Task.Delay(KeepAliveInterval, ct);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or WebSocketException or ObjectDisposedException)
        {
            // The socket closed; the reader loop reports it.
        }
    }

    public async Task<Page> FetchAsync(Direction direction, ulong? after, CancellationToken ct = default)
    {
        using var response = await SendAsync(HttpMethod.Get, $"/{direction.Path()}?after={after ?? 0}&limit=16", null, ct);
        var body = await response.Content.ReadAsByteArrayAsync(ct);
        return new Page(Wire.Split(body), Header(response, "X-Relay-More") == "1");
    }

    public async Task<ulong?> LastSequenceAsync(Direction direction, CancellationToken ct = default)
    {
        using var response = await SendAsync(HttpMethod.Head, $"/{direction.Path()}", null, ct);
        return ulong.TryParse(Header(response, "X-Relay-Last"), out var last) ? last : null;
    }

    public async Task PruneAsync(Direction direction, ulong through, CancellationToken ct = default) =>
        (await SendAsync(HttpMethod.Delete, $"/{direction.Path()}?through={through}", null, ct)).Dispose();

    public async Task EraseAsync(CancellationToken ct = default) =>
        (await SendAsync(HttpMethod.Delete, "", null, ct)).Dispose();

    /// <summary>
    /// A WebSocket that announces each sequence the other side writes. Calls
    /// <paramref name="onSequence"/> until the socket closes or <paramref name="ct"/> fires.
    /// Only writes after <paramref name="onOpen"/> are announced: fetch once after it.
    /// </summary>
    public async Task WatchAsync(
        Direction direction, Action<ulong> onSequence, Action? onOpen = null, CancellationToken ct = default)
    {
        using var socket = await ConnectAsync($"/{direction.Path()}/watch", ct);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var sending = new SemaphoreSlim(1, 1);
        var keepAlive = KeepAliveAsync(socket, sending, stop.Token);
        onOpen?.Invoke();
        var buffer = new byte[32];
        try
        {
            while (socket.State == WebSocketState.Open)
            {
                var result = await socket.ReceiveAsync(buffer, ct);
                if (result.MessageType == WebSocketMessageType.Close) break;
                // "pong" is not a number and is skipped.
                if (result.EndOfMessage && ulong.TryParse(Encoding.ASCII.GetString(buffer, 0, result.Count), out var s))
                    onSequence(s);
            }
        }
        finally
        {
            await stop.CancelAsync();
            await keepAlive;
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method, string path, HttpContent? content, CancellationToken ct, string? notify = null)
    {
        using var request = new HttpRequestMessage(method, Mailbox + path) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _credentials.BearerToken);
        if (notify is not null) request.Headers.Add("X-Relay-Notify", notify);
        var response = await _http.SendAsync(request, ct);
        if (response.IsSuccessStatusCode) return response;
        using (response)
        {
            var code = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "unauthorized",
                HttpStatusCode.Conflict => "sequence_conflict",
                HttpStatusCode.PaymentRequired or HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.InsufficientStorage => "quota_exceeded",
                HttpStatusCode.TooManyRequests => "rate_limited",
                _ => "unavailable",
            };
            ulong? last = ulong.TryParse(Header(response, "X-Relay-Last"), out var l) ? l : null;
            var retryAfter = response.Headers.RetryAfter?.Delta;
            throw new RelayException(code, (int)response.StatusCode, last, retryAfter);
        }
    }

    private static string? Header(HttpResponseMessage r, string name) =>
        r.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() : null;
}

/// <summary>What a <see cref="SignalChannel"/> reports.</summary>
public abstract record SignalEvent
{
    private SignalEvent() { }

    /// <summary>The other device connected (<c>true</c>) or left (<c>false</c>).</summary>
    public sealed record Peer(bool Present) : SignalEvent;

    /// <summary>An opened message from the other device: an offer, answer or candidate.</summary>
    public sealed record Message(byte[] Data) : SignalEvent;
}

/// <summary>
/// A rendezvous through the relay (its signal extension), for setting up a
/// direct WebRTC connection. Frames are sealed under signal keys the relay
/// does not have. Enumerating <see cref="EventsAsync"/> connects; send once
/// the other side is present. A newer connection for the same side replaces
/// this one (<see cref="CloseCode"/> 4000).
/// </summary>
public sealed class SignalChannel : IAsyncDisposable
{
    private readonly Relay _relay;
    private readonly SemaphoreSlim _sending = new(1, 1);
    private ClientWebSocket? _socket;
    private ulong _lastSent;
    private ulong? _lastReceived;

    internal SignalChannel(Relay relay, Direction sends)
    {
        _relay = relay;
        Sends = sends;
    }

    public Direction Sends { get; }
    public Direction Receives => Sends.Reversed();

    /// <summary>Why the relay closed the socket: 4000 replaced, 1003/1009 bad frame, 1008 rate limited.</summary>
    public int? CloseCode { get; private set; }

    /// <summary>Connects and yields events until the socket closes or <paramref name="ct"/> fires.</summary>
    public async IAsyncEnumerable<SignalEvent> EventsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        await CloseAsync();
        var side = Sends == Direction.P2C ? "primary" : "companion";
        var socket = await _relay.ConnectAsync($"/signal/{side}", ct);
        _socket = socket;
        _lastReceived = null;
        CloseCode = null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var keepAlive = Relay.KeepAliveAsync(socket, _sending, stop.Token);
        var buffer = new byte[SignalFrame.MaxFrameBytes];
        try
        {
            while (await ReceiveAsync(socket, buffer, ct) is { } received)
            {
                var (type, count) = received;
                if (type == WebSocketMessageType.Text)
                {
                    var text = Encoding.UTF8.GetString(buffer, 0, count);
                    if (text == "peer 1") yield return new SignalEvent.Peer(true);
                    else if (text == "peer 0") yield return new SignalEvent.Peer(false);
                    continue;
                }
                Opened opened;
                try
                {
                    opened = SignalFrame.Open(
                        buffer.AsSpan(0, count), Receives, _lastReceived, SignalFrame.Now(), _relay.Credentials);
                }
                catch (ZeroByteException)
                {
                    continue; // Forged, replayed, stale or for the other side.
                }
                _lastReceived = opened.Sequence;
                yield return new SignalEvent.Message(opened.Plaintext);
            }
        }
        finally
        {
            await stop.CancelAsync();
            await keepAlive;
            CloseCode = (int?)socket.CloseStatus;
            if (socket.State == WebSocketState.CloseReceived)
            {
                try { await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None); }
                catch (WebSocketException) { }
            }
            if (ReferenceEquals(_socket, socket)) _socket = null;
            socket.Dispose();
        }
    }

    // One whole message, or null once the socket closed. Oversized messages
    // come back as empty binary ones, which never open.
    private static async Task<(WebSocketMessageType, int)?> ReceiveAsync(
        ClientWebSocket socket, byte[] buffer, CancellationToken ct)
    {
        try
        {
            var count = 0;
            var oversized = false;
            while (true)
            {
                var result = await socket.ReceiveAsync(buffer.AsMemory(oversized ? 0 : count), ct);
                if (result.MessageType == WebSocketMessageType.Close) return null;
                if (!oversized) count += result.Count;
                if (result.EndOfMessage)
                    return oversized ? (WebSocketMessageType.Binary, 0) : (result.MessageType, count);
                if (count == buffer.Length) oversized = true;
            }
        }
        catch (Exception e) when (e is WebSocketException or ObjectDisposedException)
        {
            return null;
        }
    }

    /// <summary>Seals and sends one message of at most <see cref="SignalFrame.MaxPlaintextBytes"/>.</summary>
    public async Task SendAsync(byte[] plaintext, CancellationToken ct = default)
    {
        var socket = _socket;
        if (socket is null || socket.State != WebSocketState.Open) throw new RelayException("not_connected", 0);
        await _sending.WaitAsync(ct);
        try
        {
            var now = SignalFrame.Now();
            var counter = now > _lastSent ? now : _lastSent + 1;
            var frame = SignalFrame.Seal(plaintext, Sends, counter, _relay.Credentials);
            _lastSent = counter;
            await socket.SendAsync(frame, WebSocketMessageType.Binary, true, ct);
        }
        finally
        {
            _sending.Release();
        }
    }

    /// <summary>Closes the socket; <see cref="EventsAsync"/> then ends.</summary>
    public async Task CloseAsync()
    {
        var socket = _socket;
        if (socket?.State != WebSocketState.Open) return;
        await _sending.WaitAsync();
        try { await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None); }
        catch (Exception e) when (e is WebSocketException or ObjectDisposedException) { }
        finally { _sending.Release(); }
    }

    public async ValueTask DisposeAsync() => await CloseAsync();
}

/// <summary>
/// One side of a paired link: sends in its own direction, receives, opens and
/// prunes in the other. Operations run one at a time. Persist <see cref="LastReceived"/>.
/// </summary>
public sealed class Link(Credentials credentials, Direction sends, IRelayTransport relay, ulong? lastReceived = null)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _claimed;
    private ulong? _next;

    public Direction Sends { get; } = sends;
    public Direction Receives { get; } = sends.Reversed();
    public ulong? LastReceived { get; private set; } = lastReceived;

    private async Task EnsureClaimedAsync(CancellationToken ct)
    {
        if (_claimed) return;
        await relay.ClaimAsync(ct);
        _claimed = true;
    }

    /// <summary>Seals and stores one message; returns its sequence.</summary>
    public Task<ulong> SendAsync(byte[] plaintext, CancellationToken ct = default) =>
        SendAsync(plaintext, Notify.None, ct);

    /// <summary>
    /// Seals and stores one message and asks the relay to wake the other device
    /// (<see cref="Notify.Alert"/> or <see cref="Notify.Silent"/>); returns its sequence.
    /// </summary>
    public async Task<ulong> SendAsync(byte[] plaintext, Notify notify, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await EnsureClaimedAsync(ct);
            var sequence = _next ?? (await relay.LastSequenceAsync(Sends, ct) ?? 0) + 1;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var envelope = Envelope.Seal(plaintext, Sends, sequence, credentials);
                try
                {
                    await relay.PutAsync(envelope, Sends, sequence, notify, ct);
                    _next = sequence + 1;
                    return sequence;
                }
                catch (RelayException e) when (e.Code == "sequence_conflict")
                {
                    sequence = (e.Last ?? sequence) + 1;
                }
            }
            throw new RelayException("sequence_conflict", 409, sequence - 1);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Fetches, opens and prunes everything the other side wrote since
    /// <see cref="LastReceived"/>. Envelopes that do not open are skipped and pruned.
    /// </summary>
    public async Task<List<Opened>> ReceiveAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await EnsureClaimedAsync(ct);
            var received = new List<Opened>();
            var cursor = LastReceived;
            ulong? seen = null;
            while (true)
            {
                var page = await relay.FetchAsync(Receives, cursor, ct);
                var before = cursor;
                foreach (var envelope in page.Envelopes)
                {
                    ulong sequence;
                    try { sequence = Envelope.ReadHeader(envelope).Sequence; }
                    catch (ZeroByteException) { continue; }
                    if (cursor is null || sequence > cursor) cursor = sequence;
                    if (seen is null || sequence > seen) seen = sequence;
                    try
                    {
                        var opened = Envelope.Open(envelope, Receives, LastReceived, credentials);
                        received.Add(opened);
                        LastReceived = opened.Sequence;
                    }
                    catch (ZeroByteException)
                    {
                        // Forged, replayed or damaged: it can never open later.
                    }
                }
                if (!page.More || cursor == before) break;
            }
            if (seen is { } through) await relay.PruneAsync(Receives, through, ct);
            return received;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Deletes the mailbox for both sides. Use when the devices unpair.</summary>
    public async Task EraseAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await relay.EraseAsync(ct);
            _claimed = false;
            _next = null;
        }
        finally
        {
            _gate.Release();
        }
    }
}

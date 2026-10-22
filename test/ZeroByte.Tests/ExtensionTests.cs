// The relay's extensions: push, rate limits, ICE and signal frames. Signal
// known answers come from the independent reference (relay-v1.json).

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using ZeroByte.Apns;
using ZeroByte.Fcm;

namespace ZeroByte.Tests;

public class ExtensionTests
{
    private static readonly JsonElement V =
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "relay-v1.json"))).RootElement;

    private static readonly JsonElement S = V.GetProperty("signal");

    private static byte[] Hex(string s) => Convert.FromHexString(s);
    private static string Hex(byte[] b) => Convert.ToHexStringLower(b);
    private static ulong U(JsonElement o, string name) => ulong.Parse(o.GetProperty(name).GetString()!);

    private static Credentials Creds(int i)
    {
        var c = V.GetProperty("credentials")[i];
        return new Credentials(Hex(c.GetProperty("linkKey").GetString()!), Hex(c.GetProperty("linkId").GetString()!));
    }

    private static void RequireAead() =>
        Assert.SkipUnless(Envelope.IsSupported, "ChaCha20-Poly1305 is not supported on this OS");

    [Fact]
    public void SignalKeysMatchTheVectors()
    {
        Assert.Equal(300_000UL, S.GetProperty("windowMilliseconds").GetUInt64());
        Assert.Equal(SignalFrame.MaxFrameBytes, S.GetProperty("maximumFrameBytes").GetInt32());
        var i = 0;
        foreach (var keys in S.GetProperty("keys").EnumerateArray())
        {
            var c = Creds(i++);
            Assert.Equal(keys.GetProperty("p2cKey").GetString(), Hex(c.SignalKey(Direction.P2C)));
            Assert.Equal(keys.GetProperty("c2pKey").GetString(), Hex(c.SignalKey(Direction.C2P)));
        }
    }

    [Fact]
    public void SignalFramesSealAndOpenAsTheVectorsSay()
    {
        RequireAead();
        foreach (var f in S.GetProperty("frames").EnumerateArray())
        {
            var c = Creds(f.GetProperty("credentials").GetInt32());
            var d = (Direction)f.GetProperty("direction").GetInt32();
            var frame = SignalFrame.Seal(
                Hex(f.GetProperty("plaintext").GetString()!), d, U(f, "counter"), c,
                Hex(f.GetProperty("nonce").GetString()!));
            Assert.Equal(f.GetProperty("frame").GetString(), Hex(frame));
            var opened = SignalFrame.Open(frame, d, null, U(f, "now"), c);
            Assert.Equal(U(f, "counter"), opened.Sequence);
            Assert.Equal(f.GetProperty("plaintext").GetString(), Hex(opened.Plaintext));
        }
    }

    [Fact]
    public void EverySignalRejectionIsRefusedWithItsError()
    {
        RequireAead();
        foreach (var r in S.GetProperty("rejections").EnumerateArray())
        {
            ulong? after = r.GetProperty("after").ValueKind == JsonValueKind.Null ? null : U(r, "after");
            var error = Assert.Throws<ZeroByteException>(() => SignalFrame.Open(
                Hex(r.GetProperty("frame").GetString()!), (Direction)r.GetProperty("direction").GetInt32(),
                after, U(r, "now"), Creds(r.GetProperty("credentials").GetInt32())));
            Assert.Equal(r.GetProperty("error").GetString(), error.Code);
        }
    }

    [Fact]
    public void PushRegistrationsAreGenericAndApnsIsItsOwnPackage()
    {
        var tag = PushRegistration.RandomTag();
        Assert.Matches("^[A-Za-z0-9_-]{22}$", tag);
        var apns = Apns.Apns.Registration([0xab, 0x01], ApnsEnvironment.Development, tag, "New message");
        var json = JsonDocument.Parse(apns.ToJson()).RootElement;
        Assert.Equal("apns", json.GetProperty("service").GetString());
        Assert.Equal("ab01", json.GetProperty("token").GetString());
        Assert.Equal("development", json.GetProperty("environment").GetString());
        Assert.Equal(tag, json.GetProperty("tag").GetString());
        Assert.Equal("New message", json.GetProperty("alert").GetString());

        var other = new PushRegistration("example", new Dictionary<string, string> { ["endpoint"] = "x" }, "t");
        var o = JsonDocument.Parse(other.ToJson()).RootElement;
        Assert.Equal("example", o.GetProperty("service").GetString());
        Assert.False(o.TryGetProperty("alert", out _));
        // The service's own fields cannot override the common ones.
        var sneaky = new PushRegistration("a", new Dictionary<string, string> { ["service"] = "b", ["tag"] = "c" }, "t");
        Assert.Equal("a", JsonDocument.Parse(sneaky.ToJson()).RootElement.GetProperty("service").GetString());

        Assert.Equal("abc", Apns.Apns.TagFromPayload("""{"aps":{},"zerobyte":{"tag":"abc"}}"""));
        Assert.Null(Apns.Apns.TagFromPayload("""{"zerobyte":{"tag":"a b"}}"""));
        Assert.Null(Apns.Apns.TagFromPayload("""{"zerobyte":{"tag":7}}"""));
        Assert.Null(Apns.Apns.TagFromPayload("not json"));
    }

    [Fact]
    public void FcmRegistrationsAndPushesAreReadAsTheRelaySendsThem()
    {
        var token = "cX9" + new string('a', 60) + ":APA91b" + string.Concat(Enumerable.Repeat("B_-", 30));
        var json = JsonDocument.Parse(Fcm.Fcm.Registration(token, "team-3", "New data").ToJson()).RootElement;
        Assert.Equal("fcm", json.GetProperty("service").GetString());
        Assert.Equal(token, json.GetProperty("token").GetString());
        Assert.Equal("New data", json.GetProperty("alert").GetString());
        Assert.Throws<ArgumentException>(() => Fcm.Fcm.Registration("short", "t"));

        Assert.Equal(
            new FcmPush("team-3", Notify.Alert, "New data"),
            Fcm.Fcm.Parse(new Dictionary<string, string>
            {
                ["zerobyte_tag"] = "team-3", ["zerobyte_notify"] = "alert", ["zerobyte_alert"] = "New data",
            }));
        Assert.Equal(
            new FcmPush("team-3", Notify.Silent, null),
            Fcm.Fcm.Parse(new Dictionary<string, string>
            {
                ["zerobyte_tag"] = "team-3", ["zerobyte_notify"] = "silent", ["zerobyte_alert"] = "x",
            }));
        Assert.Null(Fcm.Fcm.Parse(new Dictionary<string, string> { ["zerobyte_tag"] = "a/b", ["zerobyte_notify"] = "alert" }));
        Assert.Null(Fcm.Fcm.Parse(new Dictionary<string, string> { ["zerobyte_tag"] = "t", ["zerobyte_notify"] = "loud" }));
        Assert.Null(Fcm.Fcm.Parse(new Dictionary<string, string> { ["title"] = "from another sender" }));
    }

    private sealed class Recorder(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public readonly List<(HttpRequestMessage Request, string? Body)> Requests = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            Requests.Add((request, body));
            return answer(request);
        }
    }

    [Fact]
    public async Task TheRelaySendsNotifyPushAndIceRequestsAndReportsRateLimits()
    {
        var c = Creds(0);
        var recorder = new Recorder(r => r.RequestUri!.AbsolutePath.EndsWith("/ice")
            ? new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"iceServers":[{"urls":["stun:stun.example.com"]},{"urls":["turn:t.example.com"],"username":"u","credential":"p"}],"ttl":3600}"""),
            }
            : new HttpResponseMessage(HttpStatusCode.NoContent));
        var relay = new Relay("app", c, new Uri("https://relay.example.com/v1/"), new HttpClient(recorder));

        await relay.PutAsync([1], Direction.P2C, 3, Notify.Alert);
        await relay.PutAsync([1], Direction.P2C, 4);
        await relay.RegisterPushAsync(Apns.Apns.Registration([1], ApnsEnvironment.Production, "t"), Direction.C2P);
        await relay.UnregisterPushAsync(Direction.C2P);
        var ice = await relay.IceServersAsync();

        var r = recorder.Requests;
        Assert.Equal(["alert"], r[0].Request.Headers.GetValues("X-Relay-Notify"));
        Assert.False(r[1].Request.Headers.Contains("X-Relay-Notify"));
        Assert.Equal(HttpMethod.Put, r[2].Request.Method);
        Assert.EndsWith("/c2p/push", r[2].Request.RequestUri!.AbsolutePath);
        Assert.Equal("01", JsonDocument.Parse(r[2].Body!).RootElement.GetProperty("token").GetString());
        Assert.Equal(HttpMethod.Delete, r[3].Request.Method);
        Assert.Equal(3600, ice.Ttl);
        Assert.Equal("p", ice.IceServers[1].Credential);
        Assert.Equal(["stun:stun.example.com"], ice.IceServers[0].Urls);

        var limited = new Recorder(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
            return response;
        });
        var error = await Assert.ThrowsAsync<RelayException>(() =>
            new Relay("app", c, new Uri("https://relay.example.com/v1/"), new HttpClient(limited)).IceServersAsync());
        Assert.Equal("rate_limited", error.Code);
        Assert.Equal(TimeSpan.FromSeconds(7), error.RetryAfter);
    }

    /// <summary>
    /// Against a relay whose app enables signal and push:
    /// RELAY_BASE=… RELAY_SIGNAL_APP=&lt;id&gt; dotnet test
    /// </summary>
    [Fact]
    public async Task ExtensionsAgainstARealRelay()
    {
        var @base = Environment.GetEnvironmentVariable("RELAY_BASE");
        var app = Environment.GetEnvironmentVariable("RELAY_SIGNAL_APP");
        Assert.SkipWhen(string.IsNullOrEmpty(@base) || string.IsNullOrEmpty(app), "RELAY_BASE and RELAY_SIGNAL_APP not set");
        RequireAead();
        var c = new Credentials(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(16));
        var relay = new Relay(app!, c, new Uri(@base!));
        var phone = new Link(c, Direction.P2C, relay);
        await phone.SendAsync(Encoding.UTF8.GetBytes("claim"), Notify.Alert);
        await relay.RegisterPushAsync(
            Apns.Apns.Registration(RandomNumberGenerator.GetBytes(32), ApnsEnvironment.Development, PushRegistration.RandomTag()),
            Direction.C2P);
        try
        {
            Assert.NotNull((await relay.IceServersAsync()).IceServers);
        }
        catch (RelayException e) when (e.Status == 404)
        {
            // This relay has no STUN/TURN configured.
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var primary = relay.Signal(Direction.P2C);
        await using var companion = new Relay(app!, c, new Uri(@base!)).Signal(Direction.C2P);
        var primaryEvents = primary.EventsAsync(cts.Token).GetAsyncEnumerator(cts.Token);
        var companionEvents = companion.EventsAsync(cts.Token).GetAsyncEnumerator(cts.Token);
        // Each side connects on its first MoveNextAsync; both then hear "peer 1".
        var joined = await Task.WhenAll(
            primaryEvents.MoveNextAsync().AsTask(), companionEvents.MoveNextAsync().AsTask());
        Assert.Equal([true, true], joined);
        Assert.Equal(new SignalEvent.Peer(true), primaryEvents.Current);
        Assert.Equal(new SignalEvent.Peer(true), companionEvents.Current);

        await companion.SendAsync(Encoding.UTF8.GetBytes("offer"));
        while (await primaryEvents.MoveNextAsync())
            if (primaryEvents.Current is SignalEvent.Message m)
            {
                Assert.Equal("offer", Encoding.UTF8.GetString(m.Data));
                break;
            }
        await companion.CloseAsync();
        Assert.True(await primaryEvents.MoveNextAsync());
        Assert.Equal(new SignalEvent.Peer(false), primaryEvents.Current);
        await primaryEvents.DisposeAsync();
        await companionEvents.DisposeAsync();
        await phone.EraseAsync();
    }
}

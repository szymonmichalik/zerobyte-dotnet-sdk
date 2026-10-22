# ZeroByte .NET SDK

The .NET client for ZeroByte, an end-to-end encrypted relay between two paired
devices of one app. It targets .NET 10 and suits Windows apps (WinUI, WPF,
MAUI) and services. It runs wherever .NET has ChaCha20-Poly1305: Windows 10
20H2 and newer, Linux with OpenSSL 1.1+, and macOS. It has no dependencies
beyond the base class library.

## How it works

Two devices pair once and agree a 32-byte link key and a link id. From these,
each device derives the mailbox name, an access token and one encryption key
per direction. Every message is sealed with ChaCha20-Poly1305 on the device
that sends it. The relay holds the sealed envelope until the other device
collects it, and it never has a key to open it with.

The wire format is specified in
[Relay Protocol v1](https://github.com/zerobyte-cloud/zerobyte-protocol/blob/master/relay-v1.md).

## Installation

The package is not on NuGet yet. Reference the project, or build a package and
add it from a local folder:

```sh
git clone https://github.com/zerobyte-cloud/zerobyte-dotnet-sdk.git
dotnet pack zerobyte-dotnet-sdk/src/ZeroByte -o ./packages
dotnet add package ZeroByte --source ./packages
```

| Package | What it is |
| --- | --- |
| `ZeroByte` | Links, envelopes, the relay, push registration, signal and ICE. |
| `ZeroByte.Apns` | APNs registrations and push payloads, for apps that use Apple push. |
| `ZeroByte.Fcm` | FCM registrations and push parsing, for .NET MAUI on Android. |

## Usage

```csharp
using System.Threading.Channels;
using ZeroByte;

// Both devices agreed linkKey (32 bytes) and linkID when they paired.
var credentials = new Credentials(linkKey, linkID);
var relay = new Relay("<your app id>", credentials,
    new Uri("https://relay.example.com/v1/")); // your relay
var link = new Link(credentials, Direction.C2P, relay, savedLastReceived);

await link.SendAsync("hello"u8.ToArray());

// The watch socket only announces sequence numbers; fetch on open and on each one.
var wake = Channel.CreateUnbounded<ulong>();
_ = relay.WatchAsync(Direction.P2C,
    onSequence: s => wake.Writer.TryWrite(s),
    onOpen: () => wake.Writer.TryWrite(0),
    ct: cancellation);

await foreach (var _ in wake.Reader.ReadAllAsync(cancellation))
{
    foreach (var message in await link.ReceiveAsync(cancellation))
        Handle(message.Plaintext);
}
```

- **Pairing** is the app's job: for example a QR code carrying a fresh 32-byte
  key, or an ECDH exchange confirmed by comparing digits on both screens. On
  Windows, protect the link key with DPAPI or the Credential Locker.
- **Directions.** The primary holds the source of truth and sends
  `Direction.P2C`; the companion sends `Direction.C2P`.
- **State.** Persist `link.LastReceived` and pass it back on the next start, so
  messages are not delivered twice.
- **Unpairing.** Call `await link.EraseAsync()` to delete the mailbox at once.
- **The relay.** The third argument of `Relay` is your relay's `/v1/` URL,
  with the trailing slash. There is no default.
- **Old Windows builds.** Check `Envelope.IsSupported` before use.
- **GUID link ids.** `new Credentials(linkKey, Guid)` reads the GUID in RFC 4122
  byte order, the same as the other SDKs.

The app id identifies your app on your relay. Generate one with
`npm run app-id` in a clone of
[zerobyte-relay](https://github.com/zerobyte-cloud/zerobyte-relay) and add it
to `RELAY_APPS`.

### Relay extensions

These work on relays and apps that enable them; elsewhere the relay answers
`404` (`RelayException` code `unavailable`). Any call may throw code
`rate_limited` with `RetryAfter`: wait and retry.

**Push.** The reader registers on the direction it reads; the writer asks for
a push per message. APNs (for .NET MAUI on iOS and Mac Catalyst) is the
separate package `ZeroByte.Apns`, as it is a separate module in the relay:

```csharp
using ZeroByte.Apns;

await relay.RegisterPushAsync(
    Apns.Registration(deviceToken, ApnsEnvironment.Production, tag, alert: "New message"),
    Direction.P2C);
await link.SendAsync(bytes, Notify.Alert); // on the other device
```

The push carries only `{"zerobyte":{"tag":"…"}}`; `Apns.TagFromPayload`
reads it. On Android, `ZeroByte.Fcm` does the same for the relay's FCM module:

```csharp
using ZeroByte.Fcm;

await relay.RegisterPushAsync(Fcm.Registration(fcmToken, tag, alert: "New data"), Direction.P2C);
if (Fcm.Parse(message.Data) is { } push) { /* find the link by push.Tag, receive */ }
```

For another push service the relay has, build a
`new PushRegistration(service, fields, tag)`.

**Signal and ICE.** A rendezvous for a direct WebRTC connection. Frames are
sealed under signal keys derived from the link key; the relay cannot read or
forge them.

```csharp
await using var channel = relay.Signal(Direction.P2C);
var ice = await relay.IceServersAsync();
await foreach (var e in channel.EventsAsync(cancellation))
{
    if (e is SignalEvent.Peer { Present: true }) await channel.SendAsync(offer);
    if (e is SignalEvent.Message m) Handle(m.Data); // answer, candidates
}
```

`WatchAsync` and signal sockets send `ping` every 30 seconds, which keeps NATs
open and tells the relay the reader is awake, so it sends no push.

## Testing

```sh
dotnet test
```

This runs the protocol vectors and the `Link` tests. To also test against a
real relay, start one locally (see zerobyte-relay) and run:

```sh
RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<app id> dotnet test
```

For the extensions, add an app with `signal` and `push=<topic>` and set
`RELAY_SIGNAL_APP=<that app id>` as well.

`test/ZeroByte.Tests/relay-v1.json` is copied from the independent reference in
[zerobyte-protocol](https://github.com/zerobyte-cloud/zerobyte-protocol/tree/master/spec).
Never regenerate it from this library.

## Licence

Apache-2.0, see [`LICENSE`](LICENSE).

## About ZeroByte

ZeroByte is an open-source project by Szymon Michalik: the protocol, the relay
and the SDKs. To use ZeroByte in your app, run your own relay (see
[zerobyte-relay](https://github.com/zerobyte-cloud/zerobyte-relay)) or register the app on
the hosted relay at [console.zerobyte.cloud](https://console.zerobyte.cloud).

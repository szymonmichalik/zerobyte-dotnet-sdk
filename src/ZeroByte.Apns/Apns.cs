// ZeroByte.Apns: the APNs side of the relay's push extension. A separate
// package: an app that does not use Apple push notifications (.NET MAUI on
// iOS or Mac Catalyst does) references only ZeroByte.

using System.Text.Json;

namespace ZeroByte.Apns;

/// <summary>
/// Which APNs host the relay sends to. Debug builds signed with a development
/// provisioning profile get development tokens.
/// </summary>
public enum ApnsEnvironment
{
    Production,
    Development,
}

public static class Apns
{
    /// <summary>A registration for the relay's APNs module.</summary>
    /// <param name="deviceToken">The token iOS gave the app for remote notifications.</param>
    /// <param name="environment"><see cref="ApnsEnvironment.Development"/> for debug builds.</param>
    /// <param name="tag">Comes back in the push. Random per link (<see cref="PushRegistration.RandomTag"/>): Apple sees it.</param>
    /// <param name="alert">The visible text if the notification service extension cannot replace it in time.</param>
    public static PushRegistration Registration(
        ReadOnlySpan<byte> deviceToken, ApnsEnvironment environment, string tag, string? alert = null) =>
        new(
            "apns",
            new Dictionary<string, string>
            {
                ["token"] = Convert.ToHexStringLower(deviceToken),
                ["environment"] = environment == ApnsEnvironment.Development ? "development" : "production",
            },
            tag,
            alert);

    /// <summary>
    /// The tag a ZeroByte push carries (<c>{"zerobyte":{"tag":…}}</c>), or null
    /// when the payload is not from a ZeroByte relay. Look the link up by it,
    /// then receive.
    /// </summary>
    public static string? TagFromPayload(string payloadJson)
    {
        try
        {
            using var document = JsonDocument.Parse(payloadJson);
            return TagFromPayload(document.RootElement);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static string? TagFromPayload(JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object
            || !payload.TryGetProperty("zerobyte", out var zerobyte)
            || zerobyte.ValueKind != JsonValueKind.Object
            || !zerobyte.TryGetProperty("tag", out var value)
            || value.ValueKind != JsonValueKind.String)
            return null;
        var tag = value.GetString()!;
        return tag.Length is > 0 and <= 64 && tag.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-') ? tag : null;
    }
}

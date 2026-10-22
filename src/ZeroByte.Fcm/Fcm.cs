// ZeroByte.Fcm: the FCM side of the relay's push extension. A separate
// package: an app that does not use Firebase Cloud Messaging (.NET MAUI on
// Android does) references only ZeroByte.

namespace ZeroByte.Fcm;

/// <summary>
/// One ZeroByte push: look the link up by <see cref="Tag"/>, then receive. For
/// <see cref="Notify.Alert"/>, show a notification with what you opened, or with
/// <see cref="Alert"/> when the envelope cannot be fetched in time.
/// </summary>
public sealed record FcmPush(string Tag, Notify Notify, string? Alert);

public static class Fcm
{
    /// <summary>A registration for the relay's FCM module.</summary>
    /// <param name="token">The FCM registration token.</param>
    /// <param name="tag">Comes back in the push. Random per link (<see cref="PushRegistration.RandomTag"/>): Google sees it.</param>
    /// <param name="alert">The visible text if the app cannot open the envelope in time.</param>
    public static PushRegistration Registration(string token, string tag, string? alert = null)
    {
        if (token.Length is < 32 or > 1024 || !token.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or ':' or '-'))
            throw new ArgumentException("An FCM registration token.", nameof(token));
        return new("fcm", new Dictionary<string, string> { ["token"] = token }, tag, alert);
    }

    /// <summary>
    /// The ZeroByte push in an FCM message's data, or null when the message is
    /// not from a ZeroByte relay. Every ZeroByte FCM message is data-only.
    /// </summary>
    public static FcmPush? Parse(IReadOnlyDictionary<string, string> data)
    {
        if (!data.TryGetValue("zerobyte_tag", out var tag)
            || tag.Length is 0 or > 64
            || !tag.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-'))
            return null;
        var notify = data.GetValueOrDefault("zerobyte_notify") switch
        {
            "alert" => Notify.Alert,
            "silent" => Notify.Silent,
            _ => (Notify?)null,
        };
        if (notify is null) return null;
        return new FcmPush(tag, notify.Value, notify == Notify.Alert ? data.GetValueOrDefault("zerobyte_alert") : null);
    }
}

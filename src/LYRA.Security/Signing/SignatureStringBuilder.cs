using LYRA.Security.Internal;
using System.Globalization;
using System.Text;

namespace LYRA.Security.Signing
{
	/// <summary>
	/// Builds the canonical "string to sign" from <see cref="GenericMetadata"/>.
	///
	/// Design rules:
	/// 1) Fixed key order and names (MUST NOT change):
	///    caller, target, action, resource, payloadHash, timestamp
	/// 2) Values are UTF-8 strings; they are percent-encoded to avoid delimiter collisions
	///    with '&' and '=' (the string uses key=value pairs joined by '&').
	/// 3) No transport assumptions (HTTP/Event/etc.). The same metadata produces the same
	///    canonical string on any platform/language.
	///
	/// Output example:
	///   caller=ordersvc&target=billingsvc&action=post&resource=/api/payments
	///   &payloadHash=BASE64...&timestamp=1717084832
	///
	/// IMPORTANT:
	/// - Consumers MUST pass the exact same metadata at the receiver to rebuild this string
	///   prior to verifying the signature.
	/// - Do not localize, trim, or reformat fields after signing (e.g., timestamps).
	/// </summary>
	public static class SignatureStringBuilder
	{
		/// <summary>
		/// Builds the canonical string using a fixed order and percent-encoded values.
		/// Throws on null/empty mandatory fields to prevent ambiguous signatures.
		/// </summary>
		/// <exception cref="ArgumentNullException"/>
		/// <exception cref="ArgumentException"/>
		public static string BuildStringToSign(GenericMetadata m)
		{
			Guard.AgainstNull(m, nameof(m));
			Guard.AgainstNullOrEmpty(m.CallerSystemName, nameof(m.CallerSystemName));
			Guard.AgainstNullOrEmpty(m.TargetSystemName, nameof(m.TargetSystemName));
			Guard.AgainstNullOrEmpty(m.Action, nameof(m.Action));
			Guard.AgainstNullOrEmpty(m.Resource, nameof(m.Resource));
			Guard.AgainstNullOrEmpty(m.PayloadHash, nameof(m.PayloadHash));
			Guard.AgainstNullOrEmpty(m.Timestamp, nameof(m.Timestamp));

			// Optional: basic timestamp sanity check (unix seconds as string).
			// If you plan to support ISO-8601, validate accordingly on the server.
			// Guard.AgainstInvalidTimestamp(m.Timestamp);

			// Percent-encode values so that '&' and '=' inside values do not break the format.
			// We intentionally do NOT encode the keys: they are fixed literals.
			var caller = Escape(m.CallerSystemName);
			var target = Escape(m.TargetSystemName);
			var action = Escape(m.Action);
			var resource = Escape(m.Resource);
			var payload = Escape(m.PayloadHash);
			var timestamp = Escape(m.Timestamp);

			// Fixed keys and order. DO NOT change without a breaking version bump.
			// We avoid string interpolation for clarity and to emphasize the exact layout.
			return string.Join("&", new[]
			{
				"caller="     + caller,
				"target="     + target,
				"action="     + action,
				"resource="   + resource,
				"payloadHash="+ payload,
				"timestamp="  + timestamp
			});
		}

		/// <summary>
		/// Percent-encodes a value for safe inclusion into a key=value pair joined by '&'.
		/// Uses Uri.EscapeDataString (RFC3986-ish). Ensures deterministic casing/culture.
		/// </summary>
		private static string Escape(string value)
		{
			// Fail fast on null; empty is allowed (but we validate required fields above).
			if (value is null) throw new ArgumentNullException(nameof(value));

			// Normalize to Form C (optional) to improve cross-platform determinism
			// when non-ASCII characters are used. Remove if you want raw pass-through.
			var normalized = value.Normalize(NormalizationForm.FormC);

			// EscapeDataString is deterministic and safe for our delimiter model.
			// It encodes spaces as %20 (NOT '+'), which is desirable here.
			var escaped = Uri.EscapeDataString(normalized);

			// Ensure culture-invariant behavior (mostly redundant here but explicit).
			return string.Create(CultureInfo.InvariantCulture, $"{escaped}");
		}
	}
}

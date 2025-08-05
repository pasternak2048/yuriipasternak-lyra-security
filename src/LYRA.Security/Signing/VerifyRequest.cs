namespace LYRA.Security.Signing
{
	/// <summary>
	/// Represents a verification request sent from a client to the LYRA server.
	/// Combines the canonical metadata (input for signing) and the resulting signature.
	///
	/// This structure is the core payload of the /api/verify endpoint,
	/// and can also be used internally for local signature verification.
	/// </summary>
	public sealed class VerifyRequest
	{
		/// <summary>
		/// Canonical metadata describing the action, resource, and signature scope.
		/// Must exactly match the values that were originally signed by the sender.
		/// </summary>
		public required GenericMetadata Metadata { get; init; }

		/// <summary>
		/// Contains the algorithm and the actual signature value (Base64-encoded).
		/// Must be generated using the exact canonical string built from the metadata.
		/// </summary>
		public required SignedMetadata Signed { get; init; }

		/// <summary>
		/// Optional request ID (client-generated) used for replay protection.
		/// If provided, the server may reject duplicates within a short time window.
		/// </summary>
		public string? RequestId { get; init; }
	}
}

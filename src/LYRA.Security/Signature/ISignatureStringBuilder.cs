using LYRA.Security.Enums;

namespace LYRA.Security.Signature
{
    /// <summary>
    /// Defines a strategy for building a canonical string to sign based on a specific access context.
    /// </summary>
    public interface ISignatureStringBuilder
    {
        /// <summary>
        /// Gets the access context this builder supports (e.g., Http, Event, Grpc).
        /// </summary>
        AccessContext Context { get; }

        /// <summary>
        /// Builds the canonical string that will be used to compute or verify a signature.
        /// </summary>
        /// <param name="caller">The system name of the initiating touchpoint.</param>
        /// <param name="target">The system name of the receiving touchpoint.</param>
        /// <param name="method">The logical action or HTTP method (e.g., POST, GET, PUBLISH).</param>
        /// <param name="path">The path or topic (e.g., /api/orders, event.created).</param>
        /// <param name="payloadHash">Base64-encoded SHA-512 hash of the payload content.</param>
        /// <param name="timestamp">UTC timestamp when the signature is generated.</param>
        /// <returns>The canonical string to be signed.</returns>
        string BuildStringToSign(
            string caller,
            string target,
            string method,
            string path,
            string payloadHash,
            string timestamp);
    }
}

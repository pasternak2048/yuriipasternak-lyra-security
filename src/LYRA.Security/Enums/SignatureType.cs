namespace LYRA.Security.Enums
{
    /// <summary>
    /// Defines the algorithm type used for signing and verifying requests.
    /// </summary>
    public enum SignatureType
    {
        /// <summary>
        /// HMAC (Hash-based Message Authentication Code) signature.
        /// </summary>
        HMAC = 1,

        /// <summary>
        /// RSA asymmetric signature.
        /// </summary>
        // TODO
        // RSA = 2,
    }
}

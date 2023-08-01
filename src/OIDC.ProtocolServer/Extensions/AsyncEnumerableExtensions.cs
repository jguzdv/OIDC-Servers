namespace JGUZDV.OIDC.ProtocolServer.Extensions
{
    public static class AsyncEnumerableExtensions
    {
        public static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> enumerable, CancellationToken ct)
        {
            var result = new List<T>();
            await foreach(var element in enumerable.WithCancellation(ct)) {
                result.Add(element);
            }

            return result;
        }
    }
}

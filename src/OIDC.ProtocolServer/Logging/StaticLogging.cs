namespace JGUZDV.OIDC.ProtocolServer.Logging
{
    /// <summary>
    /// Used to create logger instances in static classes. Needs the LoggerFactory to be 
    /// set on startup!
    /// </summary>
    internal static class StaticLogging
    {
        internal static ILoggerFactory LoggerFactory { get; set; } = default!;
        internal static ILogger CreateLogger<T>() => LoggerFactory.CreateLogger<T>();
        internal static ILogger CreateLogger(string categoryName) => LoggerFactory.CreateLogger(categoryName);


        /// <summary>
        /// Get the currently available logging factory from the given service collection.
        /// </summary>
        /// <param name="services"></param>
        internal static void SetLoggerFactoryByServiceCollection(IServiceCollection services)
        {
            var sp = services.BuildServiceProvider();   
            LoggerFactory = sp.GetRequiredService<ILoggerFactory>();
        }
    }
}

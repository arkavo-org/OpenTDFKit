import Foundation

public struct Benchmark {
    let name: String
    let operation: () -> Void
    let iterations: Int

    public init(name: String, iterations: Int = 1000, operation: @escaping () -> Void) {
        self.name = name
        self.iterations = iterations
        self.operation = operation
    }

    public func run() -> (name: String, averageTime: Double) {
        var totalTime: Double = 0

        for _ in 1...iterations {
            let start = DispatchTime.now()
            operation()
            let end = DispatchTime.now()

            let nanoTime = Double(end.uptimeNanoseconds - start.uptimeNanoseconds)
            totalTime += nanoTime / 1_000_000_000 // Convert to seconds
        }

        let averageTime = totalTime / Double(iterations)
        return (name, averageTime)
    }
}

public func runBenchmarks(_ benchmarks: [Benchmark]) {
    print("Running \(benchmarks.count) benchmarks...")
    print("-----------------------------")

    for benchmark in benchmarks {
        let result = benchmark.run()
        print("\(result.name): \(result.averageTime) seconds (average over \(benchmark.iterations) iterations)")
    }
}

// Example usage:
let benchmarks = [
    Benchmark(name: "Array Sorting") {
        var arr = (1...1000).map { _ in Int.random(in: 1...1000) }
        arr.sort()
    },
    Benchmark(name: "String Concatenation", iterations: 10000) {
        var str = ""
        for _ in 1...100 {
            str += "Hello, World! "
        }
    }
]

runBenchmarks(benchmarks)

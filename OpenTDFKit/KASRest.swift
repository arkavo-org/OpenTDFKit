import Foundation

public class KASRest {
    private let baseURL: String
    private let apiKey: String

    public init(baseURL: String, apiKey: String) {
        self.baseURL = baseURL
        self.apiKey = apiKey
    }

    public func rewrap(key: String, completion: @escaping (Result<String, Error>) -> Void) {
        guard let url = URL(string: "\(baseURL)/rewrap") else {
            completion(.failure(NSError(domain: "KASClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let parameters = ["key": key]
        guard let httpBody = try? JSONSerialization.data(withJSONObject: parameters, options: []) else {
            completion(.failure(NSError(domain: "KASClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid parameters"])))
            return
        }
        request.httpBody = httpBody

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "KASClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }

            guard (200...299).contains(httpResponse.statusCode) else {
                let error = NSError(domain: "KASClient", code: httpResponse.statusCode, userInfo: [NSLocalizedDescriptionKey: "Server returned status code \(httpResponse.statusCode)"])
                completion(.failure(error))
                return
            }

            guard let data = data else {
                completion(.failure(NSError(domain: "KASClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "No data received"])))
                return
            }

            do {
                if let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let rewrappedKey = json["rewrappedKey"] as? String {
                    completion(.success(rewrappedKey))
                } else {
                    let error = NSError(domain: "KASClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response format"])
                    completion(.failure(error))
                }
            } catch {
                completion(.failure(error))
            }
        }

        task.resume()
    }
}

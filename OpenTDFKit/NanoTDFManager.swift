import Foundation

class NanoTDFManager {
    private var nanoTDFs: [Data: NanoTDF] = [:]
    private var count: Int = 0

    func addNanoTDF(_ nanoTDF: NanoTDF, withIdentifier identifier: Data) {
        nanoTDFs[identifier] = nanoTDF
        count += 1
    }

    func getNanoTDF(withIdentifier identifier: Data) -> NanoTDF? {
        nanoTDFs[identifier]
    }

    func updateNanoTDF(_ nanoTDF: NanoTDF, withIdentifier identifier: Data) {
        nanoTDFs[identifier] = nanoTDF
    }

    func removeNanoTDF(withIdentifier identifier: Data) {
        if nanoTDFs.removeValue(forKey: identifier) != nil {
            count -= 1
        }
    }

    func isEmpty() -> Bool {
        return nanoTDFs.isEmpty
    }

    func getCount() -> Int {
        return count
    }
}

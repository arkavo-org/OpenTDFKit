import Foundation

class NanoTDFManager {
    private var nanoTDFs: [Data: NanoTDF] = [:]
    
    func addNanoTDF(_ nanoTDF: NanoTDF, withIdentifier identifier: Data) {
        nanoTDFs[identifier] = nanoTDF
    }
    
    func getNanoTDF(withIdentifier identifier: Data) -> NanoTDF? {
        return nanoTDFs[identifier]
    }
    
    func updateNanoTDF(_ nanoTDF: NanoTDF, withIdentifier identifier: Data) {
        nanoTDFs[identifier] = nanoTDF
    }
    
    func removeNanoTDF(withIdentifier identifier: Data) {
        nanoTDFs.removeValue(forKey: identifier)
    }
}

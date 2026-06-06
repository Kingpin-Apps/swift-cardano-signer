import Foundation
import Testing
@testable import SwiftCardanoSigner

@Suite("CardanoPaths — CIP-1852 / CIP-1853 / CIP-1854 / CIP-36 path constants")
struct CardanoPathsTests {

    // MARK: - Default arguments

    @Test("Default constants match the canonical Cardano roles (account 0, index 0)")
    func defaultsMatchCanonicalRoles() {
        #expect(CardanoPaths.payment()  == "m/1852'/1815'/0'/0/0")
        #expect(CardanoPaths.stake()    == "m/1852'/1815'/0'/2/0")
        #expect(CardanoPaths.drep()     == "m/1852'/1815'/0'/3/0")
        #expect(CardanoPaths.ccCold()   == "m/1852'/1815'/0'/4/0")
        #expect(CardanoPaths.ccHot()    == "m/1852'/1815'/0'/5/0")
        #expect(CardanoPaths.pool()     == "m/1853'/1815'/0'/0'")
        #expect(CardanoPaths.calidus()  == "m/1854'/1815'/0'/0'")
        #expect(CardanoPaths.cip36()    == "m/1694'/1815'/0'/0/0")
    }

    // MARK: - Account / index parametrisation

    @Test("payment(account:index:) substitutes the supplied indices")
    func paymentNonDefault() {
        #expect(CardanoPaths.payment(account: 3, index: 11) == "m/1852'/1815'/3'/0/11")
    }

    @Test("stake / drep / ccCold / ccHot all substitute the role + account + index")
    func shelleyLeafSubstitution() {
        #expect(CardanoPaths.stake(account: 1, index: 5)   == "m/1852'/1815'/1'/2/5")
        #expect(CardanoPaths.drep(account: 2, index: 7)    == "m/1852'/1815'/2'/3/7")
        #expect(CardanoPaths.ccCold(account: 4, index: 9)  == "m/1852'/1815'/4'/4/9")
        #expect(CardanoPaths.ccHot(account: 6, index: 13)  == "m/1852'/1815'/6'/5/13")
    }

    @Test("pool / calidus only take an account (no leaf index)")
    func poolAndCalidusOnlyAccount() {
        #expect(CardanoPaths.pool(account: 2)     == "m/1853'/1815'/2'/0'")
        #expect(CardanoPaths.calidus(account: 3)  == "m/1854'/1815'/3'/0'")
    }

    @Test("cip36(account:address:) substitutes both indices")
    func cip36Substitution() {
        #expect(CardanoPaths.cip36(account: 1, address: 2) == "m/1694'/1815'/1'/0/2")
    }

    // MARK: - Purpose code differentiation

    @Test("Each Shelley leaf role uses a distinct role index", arguments: [
        (CardanoPaths.payment(), "/0/0"),
        (CardanoPaths.stake(),   "/2/0"),
        (CardanoPaths.drep(),    "/3/0"),
        (CardanoPaths.ccCold(),  "/4/0"),
        (CardanoPaths.ccHot(),   "/5/0"),
    ])
    func leafRoleIndices(path: String, expectedSuffix: String) {
        #expect(path.hasSuffix(expectedSuffix))
    }
}

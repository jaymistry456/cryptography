import java.math.BigInteger;
import java.util.Random;

public class PaillierEncryption {
    private BigInteger p, q, n, g, lambda;

    public void setFirstPrimeP(BigInteger p) {
        this.p = p;
    }

    public void setSecondPrimeQ(BigInteger q) {
        this.q = q;
    }

    public void setCompositeModulusN(BigInteger n) {
        this.n = n;
    }

    public void setEncryptionExponentLambda(BigInteger lambda) {
        this.lambda = lambda;
    }

    public void setGeneratorG(BigInteger g) {
        this.g = g;
    }

    public BigInteger getFirstPrimeP() {
        return p;
    }

    public BigInteger getSecondPrimeQ() {
        return q;
    }

    public BigInteger getCompositeModulusN() {
        return this.n;
    }

    public BigInteger getEncryptionExponentLambda() {
        return this.lambda;
    }

    public BigInteger getGeneratorG() {
        return this.g;
    }

    public BigInteger generateRandomBigIntegerNumber(BigInteger lowerLimit, BigInteger upperLimit) {
        BigInteger range = upperLimit.subtract(lowerLimit);
        Random randomVariable = new Random();
        int lengthOfRandomNumber = upperLimit.bitLength();
        BigInteger result = new BigInteger(lengthOfRandomNumber, randomVariable);
        if (result.compareTo(lowerLimit) < 0)
            result = result.add(lowerLimit);
        if (result.compareTo(range) >= 0)
            result = result.mod(range).add(lowerLimit);

        return result;
    }

    public void keyGeneration() {
        // calculating n = p * q
        this.setCompositeModulusN(this.p.multiply(this.q));

        // calculating lambda = LCM(p-1, q-1)
        // setting num1 = p - 1 and num2 = q - 1
        BigInteger num1 = this.p.subtract(BigInteger.ONE);
        BigInteger num2 = this.q.subtract(BigInteger.ONE);

        // calculating GCD of num1 and num2
        BigInteger gcd = num1.gcd(num2);

        // set lambda through the LCM formula
        // LCM * GCD = num1 * num2
        // LCM = (num1 * num2) / GCD
        this.setEncryptionExponentLambda((num1.multiply(num2)).divide(gcd));

        // setting g = n + 1
        this.setGeneratorG(this.n.add(BigInteger.ONE));
    }

    public BigInteger encryption(BigInteger m, BigInteger r) {
        // get the values of g and n
        BigInteger g = this.getGeneratorG();
        BigInteger n = this.getCompositeModulusN();

        // calculating ciphertext c = (g^m * r^n) mod n^2
        BigInteger c = ((g.modPow(m, n.multiply(n))).multiply(r.modPow(n, n.multiply(n)))).mod(n.multiply(n));

        return c;
    }

    public BigInteger decryption(BigInteger c) {
        // get the values of g and n
        BigInteger g = this.getGeneratorG();
        BigInteger n = this.getCompositeModulusN();
        // get the value of lambda
        BigInteger lambda = this.getEncryptionExponentLambda();

        // calculating S = L(c^lambda mod n^2) where L(x) = (x-1)/n
        BigInteger S = ((c.modPow(lambda, n.multiply(n)).subtract(BigInteger.ONE)).divide(n)).mod(n);

        // calculating modular multiplicative inverse mu = (L(g^lambda mod n2))^(-1) mod n
        BigInteger mu = ((g.modPow(lambda, n.multiply(n)).subtract(BigInteger.ONE)).divide(n)).modPow(BigInteger.valueOf(-1), n);

        // calculating the decrypted plaintext md = (S * mu) mod n
        BigInteger md = (S.multiply(mu)).mod(n);

        return md;
    }

    public static void main(String[] args) {
        // creating an instance of PaillierEncryption class
        PaillierEncryption paillier = new PaillierEncryption();
        
        // Setting primes p and q
        System.out.println();
        System.out.println("---------- Setting random prime numbers p and q ----------");
        paillier.setFirstPrimeP(new BigInteger("91384202109071442293463836021112242872202112556997233738650771115304627068435244189452217404518350934650625169787645878831492249234702966702870665364147218752886578786376766042770107058123323172961898496290467790495229761191517699758387645314555098976305458147233083947409856486295027584628343852346198294834673398056518565970306137057662042381108071850367597403128086501769091999204250111973206216989075174484334959172281822465253170809350903328437985069427319"));
        paillier.setSecondPrimeQ(new BigInteger("81461618609951926714232486073323681843605711813586129469089521881286578240351609211470308250561781558375310490543983933780038328473513066035201591085583608631590043360965785867067725207262314428957973642440166838678305658012018727393737744349209249924848069061992265051686526452564260097993214532057415090837113730859560081637862504223208931316591467688041729971515846931082731879867661935144206080893902297595573259652166808407688180529379028374251689469303983"));
        System.out.println("The first prime p = " + paillier.getFirstPrimeP());
        System.out.println("The first prime q = " + paillier.getSecondPrimeQ());
        System.out.println();

        // Key Generation
        System.out.println("-------------------- Key Generation --------------------");
        paillier.keyGeneration();
        System.out.println("The composite modulus is n = " + paillier.getCompositeModulusN());
        System.out.println("The encryption exponent lambda is = " + paillier.getEncryptionExponentLambda());
        System.out.println();

        // Encryption
        System.out.println("-------------------- Encryption --------------------");
        // generating a random message m between [0, n-1]
        BigInteger m = paillier.generateRandomBigIntegerNumber(BigInteger.ZERO, paillier.getCompositeModulusN().subtract(BigInteger.ONE));
        System.out.println("Plaintext (randomly generate) to be encrypted is m = " + m);
        // generating a random number r between [1, n-1]
        BigInteger r = paillier.generateRandomBigIntegerNumber(BigInteger.ONE, paillier.getCompositeModulusN().subtract(BigInteger.ONE));
        System.out.println("The random number is r = " + r);
        // calculating ciphertext c through encryption
        BigInteger c = paillier.encryption(m, r);
        System.out.println("Ciphertext is c = " + c);
        System.out.println();

        System.out.println("-------------------- Decryption --------------------");
        // decrypting ciphertext back to plaintext message m
        System.out.println("Ciphertext to be decrypted is c = " + c);
        BigInteger md = paillier.decryption(c);
        System.out.println("Decrypted plaintext is m = " + md);
        System.out.println();
        // checking whether the decrypted plaintext matches the original plaintext message
        if(m.equals(md)) {
            System.out.println("Decryption was successful");
        }
        else {
            System.out.println("Decryption was unsuccessful");
        }
    }
}

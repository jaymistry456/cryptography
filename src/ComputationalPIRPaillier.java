import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class ComputationalPIRPaillier {

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

        // creating an instance of ComputationalPIRPaillier class
        ComputationalPIRPaillier computationalPIRPaillier = new ComputationalPIRPaillier();

        // Setting primes p and q
        System.out.println();
        System.out.println("---------- Setting random prime numbers p and q ----------");
        computationalPIRPaillier.setFirstPrimeP(new BigInteger("91384202109071442293463836021112242872202112556997233738650771115304627068435244189452217404518350934650625169787645878831492249234702966702870665364147218752886578786376766042770107058123323172961898496290467790495229761191517699758387645314555098976305458147233083947409856486295027584628343852346198294834673398056518565970306137057662042381108071850367597403128086501769091999204250111973206216989075174484334959172281822465253170809350903328437985069427319"));
        computationalPIRPaillier.setSecondPrimeQ(new BigInteger("81461618609951926714232486073323681843605711813586129469089521881286578240351609211470308250561781558375310490543983933780038328473513066035201591085583608631590043360965785867067725207262314428957973642440166838678305658012018727393737744349209249924848069061992265051686526452564260097993214532057415090837113730859560081637862504223208931316591467688041729971515846931082731879867661935144206080893902297595573259652166808407688180529379028374251689469303983"));
        System.out.println("The first prime p = " + computationalPIRPaillier.getFirstPrimeP());
        System.out.println("The second prime q = " + computationalPIRPaillier.getSecondPrimeQ());
        System.out.println();

        // Key Generation
        System.out.println("-------------------- Key Generation --------------------");
        computationalPIRPaillier.keyGeneration();
        System.out.println("The composite modulus is n = " + computationalPIRPaillier.getCompositeModulusN());
        System.out.println("The encryption exponent lambda is = " + computationalPIRPaillier.getEncryptionExponentLambda());
        System.out.println();

        // generating database of size 200x200
        System.out.println("---------- Generating Database of size 200x200 ----------");
        // getting the value of composite modulus N
        BigInteger compositeModulusN = computationalPIRPaillier.getCompositeModulusN();
        // initializing database of size 200x200
        BigInteger[][] database = new BigInteger[200][200];
        for(int i=0 ; i<200 ; i++) {
            for(int j=0 ; j<200 ; j++) {
                // storing database values (i, j) = (i+1)*(j+1) for testing purposes
                // for example index (i=99, j=99) = (99+1)*(99+1) = 100*100 = 10000
                database[i][j] = (BigInteger.valueOf(i).add(BigInteger.ONE)).multiply(BigInteger.valueOf(j).add(BigInteger.ONE));

                // generating random values to be stored in the database where each value is in message space N between [0, N-1]
//                database[i][j] = computationalPIRPaillier.generateRandomBigIntegerNumber(BigInteger.ZERO, compositeModulusN.subtract(BigInteger.ONE));
            }
        }
        System.out.println("---------- Database of size 200x200 generated ----------");

        System.out.println();

        // Getting the index which the client wants to access
        System.out.println("---------- Client index inputs (s, t) ----------");
        Scanner reader = new Scanner(System.in);
        System.out.println("Please enter row index s between 0 and 199: ");
        int s = reader.nextInt();
        System.out.println("Please enter column index t between 0 and 199: ");
        int t = reader.nextInt();

        System.out.println();

        // Encryption
        System.out.println("-------------------- Encryption --------------------");
        // generating a random number r between [1, N-1]
        BigInteger r = computationalPIRPaillier.generateRandomBigIntegerNumber(BigInteger.ONE, compositeModulusN.subtract(BigInteger.ONE));
        System.out.println("The random number is r = " + r);

        System.out.println();

        // generating the encrypted column index vector which the user wants to access
        System.out.println("---------- Generating Encrypted Column Vector ----------");
        BigInteger[] encryptedColumnIndexVector = new BigInteger[200];
        for(int i=0 ; i<200 ; i++) {
            // each value is set to zero except the column index which the client wants to access which is set to one
            // in addition, each value in the vector array is then encrypted using Paillier Encryption
            if(i!=t) {
                encryptedColumnIndexVector[i] = computationalPIRPaillier.encryption(BigInteger.ZERO, r);
            }
            else {
                encryptedColumnIndexVector[i] = computationalPIRPaillier.encryption(BigInteger.ONE, r);
            }
        }
        System.out.println("---------- Encrypted Column Vector generated ----------");

        System.out.println();

        // performing the server side computation by using homomorphic properties of Paillier Encryption
        System.out.println("---------- Server Side Computation ----------");
        System.out.println("---------- Please wait while server is computing ----------");
        BigInteger[] encryptedAnswer = new BigInteger[200];
        for(int i=0 ; i<200 ; i++) {
            encryptedAnswer[i] = BigInteger.ONE;
            for(int j=0 ; j<200 ; j++) {
                encryptedAnswer[i] = encryptedAnswer[i].multiply(encryptedColumnIndexVector[j].modPow(database[i][j], compositeModulusN.multiply(compositeModulusN)));
            }
        }
        System.out.println("---------- Finished Server Side Computation ----------");

        System.out.println();

        System.out.println("-------------------- Decryption --------------------");
        // decrypting ciphertext back to plaintext to get the value
        BigInteger databaseDecryptedValue = computationalPIRPaillier.decryption(encryptedAnswer[s]);
        System.out.println("Decrypted database value for index (s=" + s + ",t=" + t + "): " + databaseDecryptedValue);

        // checking correctness of the above computation
        if(databaseDecryptedValue.equals(database[s][t])) {
            System.out.println("Paillier Computational PIR access successful");
        }
        else {
            System.out.println("Paillier Computational PIR access unsuccessful");
        }

    }
}

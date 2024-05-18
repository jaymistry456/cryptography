import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Random;
import java.util.Scanner;

public class LinearRegressionPaillier {
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

    public static BigInteger encoding(Float input) {
        // accepting a float input value, converting it to BigDecimal, then multiplying the BigDecimal input by 2^30,
        // then performing a floor function on the resulting BigDecimal value to remove any decimals and returning the result by
        // converting it into BigInteger
        // BigInteger(Floor(BigDecimal(Float input) * 2^30))
        return ((BigDecimal.valueOf(input)).multiply(BigDecimal.TWO.pow(30)).setScale(0, RoundingMode.FLOOR)).toBigInteger();
    }

    public static BigDecimal decoding(BigDecimal input) {
        // accepting a BigDecimal input, dividing it by 2^30, rounding the final result to 6 decimal places and returning the result
        return input.divide(BigDecimal.TWO.pow(30), 6, RoundingMode.HALF_UP);
    }

    public static void main(String[] args) {
        // creating an instance of LinearRegressionPaillier class
        LinearRegressionPaillier paillier = new LinearRegressionPaillier();

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

        // Getting the number of inputs
        Scanner reader = new Scanner(System.in);
        System.out.println("Please enter l (≥ 3): ");
        int l = reader.nextInt();

        System.out.println("----------------------------------------------");

        // initializing arrays for inputs and corresponding encoded values of inputs for Alice (x) and Bob (theta)
        // Alice
        Float[] x = new Float[l];
        BigInteger[] encodedX = new BigInteger[l];
        // Bob
        Float[] theta = new Float[l+1];
        BigInteger[] encodedTheta = new BigInteger[l+1];

        // getting input values of Alice and storing it in corresponding arrays
        System.out.println("Input x values for Alice (enter floating point numbers by pressing enter): ");
        for(int i=0 ; i<l ; i++) {
            System.out.print("x[" + i + "]: ");
            x[i] = reader.nextFloat();
            encodedX[i] = encoding(x[i]);
            System.out.println("Encoded x[" + i + "]: " + encodedX[i]);
            System.out.println();
        }

        System.out.println("----------------------------------------------");

        // getting input values of Bob and storing it in corresponding arrays
        System.out.println("Input theta values for Bob (enter floating point numbers by pressing enter): ");
        for(int i=0 ; i<(l+1) ; i++) {
            System.out.print("theta[" + i + "]: ");
            theta[i] = reader.nextFloat();
            encodedTheta[i] = encoding(theta[i]);
            System.out.println("Encoded theta[" + i + "]: " + encodedTheta[i]);
            System.out.println();
        }

        System.out.println();

        System.out.println("---------- Generating a random value for r ----------");
        // generating a random number r between [1, n-1]
        BigInteger r = paillier.generateRandomBigIntegerNumber(BigInteger.ONE, paillier.getCompositeModulusN().subtract(BigInteger.ONE));
        System.out.println("The random number is r = " + r);

        System.out.println();

        // Encryption
        // Generating encrypted values for encoded inputs of Alice Enc(encoded xi)
        System.out.println("---------- Encryption of encoded x values ----------");
        // initializing an array for storing encrypted values
        BigInteger[] encryptedX = new BigInteger[l];
        System.out.println("Encrypted vector Enc(encoded x): ");
        System.out.print("[");
        for(int i=0 ; i<l ; i++) {
            encryptedX[i] = paillier.encryption(encodedX[i], r);
            System.out.print(encryptedX[i]);
            if(i!=(l-1)) {
                System.out.println(", ");
            }
        }
        System.out.println("]");
        System.out.println();

        // Generating encrypted value for first encoded input of Bob Enc(encoded theta0)
        System.out.println("---------- Encryption of encoded theta0 ----------");
        BigInteger encryptedEncodedTheta0 = paillier.encryption(encodedTheta[0], r);
        System.out.println("Encrypted Encoded theta0 Enc[encoded theta0] is = " + encryptedEncodedTheta0);
        System.out.println();

        // Performing linear regression through homomorphic properties of Paillier Encryption
        // The function used for linear regression is as follows-
        // E(f(θ, x)) = [Enc(encoded theta[0])^(encoded 1)] * {Multiplication over i [Enc(encoded x[i])^(encoded theta[i+1])] where i is from 0 to l-1}
        // Because of homomorphic properties of Paillier Encryption, the above function evaluates to-
        // E(f(θ, x)) = [Enc(encoded theta[0] * encoded 1)] + [Enc(encoded x[0] * encoded theta[1])] + [Enc(encoded x[1] * encoded theta[2])] + ... + [Enc(encoded x[l-1] * encoded theta[l])]
        // In the above formula, I am multiplying the encrypted theta[0] (first value) by encoded value of 1 (one) because while performing
        // decoding, I have to decode the decrypted result twice as the subsequent values in the formula consists of
        // multiplication of two encoded values, that is [encoded x[i] * encoded theta[i+1]]. I am using 1 for multiplication
        // as it does not change the value of theta0, that is Enc[value]^1 = Enc[value*1] = Enc[value] in Paillier Encryption
        System.out.println("---------- Performing Linear Regression ----------");
        BigInteger n = paillier.getCompositeModulusN();
        // encoding the value of 1
        BigInteger encodedOne = encoding(1F);
        // multiplying Enc[theta0] by encoded value of 1 and assigning it as the starting point of the variable encryptedEncodedResult
        BigInteger encryptedEncodedResult = encryptedEncodedTheta0.modPow(encodedOne, n.multiply(n));
        for(int i=0 ; i<l ; i++) {
            encryptedEncodedResult = encryptedEncodedResult.multiply(encryptedX[i].modPow(encodedTheta[i+1], n.multiply(n)));
        }
        System.out.println("Encrypted Encoded result Enc(encoded f(θ, x)) = " + encryptedEncodedResult);

        System.out.println();

        System.out.println("-------------------- Decryption --------------------");
        // Decrypting encrypted encoded result to encoded result
        BigInteger decryptedEncodedResult = paillier.decryption(encryptedEncodedResult);
        System.out.println("Decrypted Encoded result Encoded f(θ, x): " + decryptedEncodedResult);

        System.out.println();

        System.out.println("-------------------- Decoding --------------------");
        // Decoding encoded result twice to get the actual value of the function
        BigDecimal decryptedDecodedResult = decoding(decoding(new BigDecimal(decryptedEncodedResult)));
        System.out.println("Decrypted Decoded final result f(θ, x) = " + decryptedDecodedResult);

    }
}


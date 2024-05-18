import java.math.BigInteger;
import java.util.Random;

public class ElgamalEncryption {
    private BigInteger p, g, x, y;

    public ElgamalEncryption(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
    }

    public BigInteger getSecretKey() {
        return this.x;
    }

    public BigInteger getPublicKey() {
        return this.y;
    }

    public static BigInteger generateRandomBigIntegerNumber(BigInteger lowerLimit, BigInteger upperLimit) {
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
        // randomly select the secret key from [1, p-1]
        this.x = generateRandomBigIntegerNumber(BigInteger.ONE, this.p.subtract(BigInteger.ONE));

        // calculate y
        this.y = this.g.modPow(this.x, this.p);
    }

    public BigInteger[] encryption(BigInteger m, BigInteger r) {
        // calculate ciphertext c1 = g^r mod p
        BigInteger c1 = this.g.modPow(r, this.p);

        // calculate ciphertext c2 = (m * y^r) mod p
        BigInteger c2 = (m.multiply(y.modPow(r, this.p))).mod(this.p);

        return new BigInteger[]{c1, c2};
    }

    public BigInteger decryption(BigInteger[] c) {
        // calculate t = c1^(-x) mod p
        BigInteger t = c[0].modPow(this.x.multiply(BigInteger.valueOf(-1)), this.p);

        // calculate decrypted message md = (c2 * t) mod p
        BigInteger md = (c[1].multiply(t)).mod(this.p);

        return md;
    }

    public static void main(String[] args) {

        // setting p and g
        System.out.println();
        System.out.println("---------- Setting a random prime p and generator g ----------");
        BigInteger p = new BigInteger("5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807");
        BigInteger g = new BigInteger("2");

        System.out.println("The first prime is p = " + p);
        System.out.println("The value of g = " + g);

        System.out.println();

        // Initializing an object of ElgamalEncryption class
        ElgamalEncryption elgamal = new ElgamalEncryption(p, g);

        // Key Generation
        System.out.println("-------------------- Key Generation --------------------");
        elgamal.keyGeneration();

        System.out.println("The secret key x = " + elgamal.getSecretKey());
        System.out.println("The public key y = " + elgamal.getPublicKey());

        System.out.println();

        // Encryption
        System.out.println("-------------------- Encryption --------------------");
        // generating a random message m between [1, p-1]
        BigInteger m = generateRandomBigIntegerNumber(BigInteger.ONE, p.subtract(BigInteger.ONE));
        System.out.println("Plaintext (randomly generate) to be encrypted is m = " + m);
        // generating a random number r between [1, p-1]
        BigInteger r = generateRandomBigIntegerNumber(BigInteger.ONE, p.subtract(BigInteger.ONE));
        System.out.println("The random number is r = " + r);
        // Generating ciphertexts c1 and c2 through encryption
        BigInteger[] c = elgamal.encryption(m, r);
        System.out.println("Ciphertext is c = (c1, c2) = (" + c[0] + ", " + c[1] + ")");

        System.out.println();

        System.out.println("-------------------- Decryption --------------------");
        // Decrypting ciphertext back to plaintext message m
        System.out.println("Ciphertext to be decrypted is c = (c1, c2) = (" + c[0] + ", " + c[1] + ")");
        BigInteger md = elgamal.decryption(c);
        System.out.println("Decrypted plaintext is m = " + md);
        System.out.println();

        if(m.equals(md)) {
            System.out.println("Decryption was successful");
        }
        else {
            System.out.println("Decryption was unsuccessful");
        }

        System.out.println();
        System.out.println("----------------------------------------------------");
        System.out.println();

        // verifying multiplicative homomorphic property of elgamal encryption
        System.out.println("---------- Elgamal Homomorphic Encryption ----------");
        // setting messages m1 and m2
        System.out.println("---------- Setting two messages m1 and m2 ----------");
        BigInteger m1 = new BigInteger("1000");
        BigInteger m2 = new BigInteger("2000");
        System.out.println("Message m1 is = " + m1);
        System.out.println("Message m2 is = " + m2);
        System.out.println();

        // generating random messages r1 and r2 from prime p
        BigInteger r1 = generateRandomBigIntegerNumber(BigInteger.ONE, p.subtract(BigInteger.ONE));
        BigInteger r2 = generateRandomBigIntegerNumber(BigInteger.ONE, p.subtract(BigInteger.ONE));
        System.out.println("Random r1 is = " + r1);
        System.out.println("Random r2 is = " + r2);
        System.out.println();

        // generating ciphertexts for c and c' for m1 and m2 respectively
        BigInteger[] ciphertext1 = elgamal.encryption(m1, r1);
        BigInteger[] ciphertext2 = elgamal.encryption(m2, r2);
        System.out.println("Ciphertext pair for message m1 is c = (c1, c2) = (" + ciphertext1[0] + ", " + ciphertext1[1] + ")");
        System.out.println("Ciphertext pair for message m2 is c' = (c1', c2') = (" + ciphertext2[0] + ", " + ciphertext2[1] + ")");
        System.out.println();

        // multiplying both ciphertexts (c1) of both messages
        BigInteger mulCiphertextsC1 = (ciphertext1[0].multiply(ciphertext2[0])).mod(p);
        System.out.println("Multiplied ciphertext value c1*c1' is : " + mulCiphertextsC1);

        // multiplying both ciphertexts (c2) of both messages
        BigInteger mulCiphertextsC2 = (ciphertext1[1].multiply(ciphertext2[1])).mod(p);
        System.out.println("Multiplied ciphertext value c2*c2' is : " + mulCiphertextsC2);

        // Multiplied ciphertext pair (C1, C2)
        System.out.println("Ciphertext pair for multiplied message m1*m2 is = (C1, C2) = (" + mulCiphertextsC1 + ", " + mulCiphertextsC2 + ")");
        System.out.println();

        // decrypting the multiplied ciphertext value
        BigInteger Md = elgamal.decryption(new BigInteger[]{mulCiphertextsC1, mulCiphertextsC2});
        System.out.println("Decrypted message for multiplied m1*m2 is = " + Md);
        System.out.println();

        // verifying the multiplicative homomorphic property of elgamal encryption
        if (Md.equals(m1.multiply(m2))) {
            System.out.println("Elgamal Encryption is Multiplicative Homomorphic");
        }
        else {
            System.out.println("Elgamal Encryption is not Multiplicative Homomorphic");
        }

    }
}

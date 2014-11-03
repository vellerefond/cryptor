package cryptor;

import java.io.Console;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

@SuppressWarnings("unused")
public class Cryptor {
	private static byte[] utf8StringToByteArray(String input)
	{
		if (input == null || input.trim().isEmpty())
			return null;
		
		return Charset.forName("UTF8").encode(input).array();
	}
	
	private static String byteArrayToUTF8String(byte[] input)
	{
		return byteArrayToUTF8String(input, true);
	}
	
	private static String byteArrayToUTF8String(byte[] input, boolean trimOutput)
	{
		if (input == null)
			return null;
		
		if (input.length == 0)
			return "";
		
		String output = Charset.forName("UTF8").decode(ByteBuffer.wrap(input)).toString();
		
		if (trimOutput)
			output = output.trim();
		
		return output;
	}
	
	private static String toHex(byte[] data, int... length)
    {
		if (data == null)
			return null;
		
		if (data.length == 0)
			return "";
		
		if (length == null || length.length == 0)
			length = new int[] { data.length };
		
		final String digits = "0123456789abcdef";
		
        StringBuffer buf = new StringBuffer();
        
        for (int i = 0; i != length[0]; i++)
        {
            int	v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }
	
	public static byte[] computeSkein(byte[] input, int... lengths)
	{
		if (input == null || input.length == 0)
			return null;
		
		if (lengths == null || lengths.length == 0)
			lengths = new int[] { 1024, 1024 };
		else if (lengths.length < 2)
			lengths = new int[] { lengths[0], 1024 };
		
		SkeinDigest skeinDigest = new SkeinDigest(lengths[0], lengths[1]);
		skeinDigest.update(input, 0, input.length);
		byte[] output = new byte[skeinDigest.getDigestSize()];
		skeinDigest.doFinal(output, 0);
		
		return output;
	}
	
	public static byte[] computeSkein(String input, int... lengths)
	{
		return computeSkein(utf8StringToByteArray(input));
	}
	
	public static byte[] computeWhirlpool(byte[] input, int... lengths)
	{
		if (input == null || input.length == 0)
			return null;
		
		WhirlpoolDigest whirlpoolDigest = new WhirlpoolDigest();
		whirlpoolDigest.update(input, 0, input.length);
		byte[] output = new byte[whirlpoolDigest.getDigestSize()];
		whirlpoolDigest.doFinal(output, 0);
		
		return output;
	}
	
	public static byte[] computeWhirlpool(String input, int... lengths)
	{
		return computeWhirlpool(utf8StringToByteArray(input), lengths);
	}
	
	private static Method getDigestMethod(String name, Class<?> inputClass)
		throws NoSuchMethodException, SecurityException
	{
		return Cryptor.class.getMethod(name, inputClass, int[].class);
	}
	
	private static byte[] digest(byte[] input, String digestName, int... lengths)
		throws
			IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException,
			SecurityException
	{
		return (byte[])getDigestMethod("compute".concat(digestName), input.getClass()).invoke(null, input, lengths);
	}
	
	private static byte[] digest(String input, String digestName, int... lengths)
		throws
			IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException,
			SecurityException
	{
		return digest(utf8StringToByteArray(input), digestName, lengths);
	}
	
	private static byte[] digest(String input, String digestName)
		throws
			IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException,
			SecurityException
	{
		return digest(input, digestName, null);
	}
	
	private static String digestHex(String input, String digestName, int... lengths)
		throws
			IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException,
			SecurityException
	{
		return toHex(digest(input, digestName, lengths)).toUpperCase();
	}
	
	private static String digestHex(String input, String digestName)
		throws
			IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException,
			SecurityException
	{
		return digestHex(input, digestName, null);
	}
	
	private static void showMessage(String title, String message, boolean useGraphicInterface, boolean prependNewLine)
	{
		if (message == null || message.isEmpty())
			return;
		if (!useGraphicInterface) {
			if (prependNewLine)
				System.out.println();
			
			System.out.println(message);
		} else {
			JOptionPane.showMessageDialog(null, message, title, JOptionPane.INFORMATION_MESSAGE);
		}
	}
	
	private static void showMessage(String title, String message, boolean prependNewLine)
	{
		showMessage(title, message, System.console() == null, prependNewLine);
	}
	
	private static void showMessage(String title, String message)
	{
		showMessage(title, message, System.console() == null, false);
	}

	private static void showError(String message)
	{
		showError(message, System.console() == null);
	}
	
	private static void showError(String message, boolean useGraphicInterface)
	{
		if (message == null || message.isEmpty())
			return;
		if (!useGraphicInterface)
			System.err.println(message);
		else
			JOptionPane.showMessageDialog(null, message, "Error", JOptionPane.ERROR_MESSAGE);
	}
	
	private static String[] getKeyWithDialog(String title, String message)
	{
		String[] key = null;
		
		JPanel panel = new JPanel();
		JLabel label = new JLabel(message);
		JPasswordField passwordField = new JPasswordField(35);
		String[] buttons = new String[] { "OK", "Cancel" };
		
		panel.add(label);
		panel.add(passwordField);
		
		int option = JOptionPane.showOptionDialog(
			null,
			panel,
			title,
			JOptionPane.NO_OPTION,
			JOptionPane.PLAIN_MESSAGE,
			null,
			buttons,
			passwordField
		);
		
		if (option == 0)
			key = new String[] { new String(passwordField.getPassword()) };
		
		passwordField.setText(new String(new char[passwordField.getPassword().length]));
		passwordField.setText(null);
		
		return key;
	}
	
	private static void errExit(String message)
	{
		errExit(message, System.console() == null);
	}
	
	private static void errExit(String message, boolean useGraphicInterface)
	{
		showError(message);
		System.exit(1);
	}
	
	private static String[] requestKey(int mode)
	{
		return requestKey(mode, System.console() == null);
	}
	
	private static String[] requestKey(int mode, boolean useGraphicInterface)
	{
		String[] key = null;
		
		try {
			Console systemConsole = null;
			
			String keyTmpPass1 = null, keyTmpPass2 = null;
			
			if (!useGraphicInterface) {
				systemConsole = System.console();
				
				if (systemConsole == null)
					throw new Exception();
				
				keyTmpPass1 = new String(systemConsole
						.readPassword(
							"Please, provide the key for the " +
								(mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption") +
								":"
						));
				
				if (keyTmpPass1 == null || keyTmpPass1.isEmpty())
					System.exit(0);
				
				if (mode == Cipher.ENCRYPT_MODE) {
					keyTmpPass2 = new String(systemConsole
							.readPassword(
								"Please, confirm the key for the " +
									(mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption") +
									":"
							));
					
					if (keyTmpPass2 == null || keyTmpPass2.isEmpty()) {
						keyTmpPass1 = new String(new char[keyTmpPass1.length()]);
						keyTmpPass1 = null;
						
						System.exit(0);
					}
				}
			} else {
				String[] keyTmpPass1Tmp = getKeyWithDialog(
					(mode == Cipher.ENCRYPT_MODE ? "Encryption" : "Decryption") + " Key",
					"Please, provide the key for the " +
						(mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption") +
						":"
				);
				
				if (keyTmpPass1Tmp == null || keyTmpPass1Tmp.length == 0) {
					keyTmpPass1 = null;
				} else {
					keyTmpPass1 = keyTmpPass1Tmp[0];
					
					if (keyTmpPass1Tmp[0] != null && !keyTmpPass1Tmp[0].isEmpty()) {
						keyTmpPass1Tmp[0] = new String(new char[keyTmpPass1Tmp[0].length()]);
						keyTmpPass1Tmp[0] = null;
						keyTmpPass1Tmp = null;
					}
				}

				if (keyTmpPass1 == null || keyTmpPass1.isEmpty())
					System.exit(0);
				
				if (mode == Cipher.ENCRYPT_MODE) {
					String[] keyTmpPass2Tmp = getKeyWithDialog(
						(mode == Cipher.ENCRYPT_MODE ? "Encryption" : "Decryption") + " Key Confirmation",
						"Please, confirm the key for the " +
							(mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption") +
							":"
					);
					
					if (keyTmpPass2Tmp == null || keyTmpPass2Tmp.length == 0) {
						keyTmpPass2 = null;
					} else {
						keyTmpPass2 = keyTmpPass2Tmp[0];
						
						if (keyTmpPass2Tmp[0] != null && !keyTmpPass2Tmp[0].isEmpty()) {
							keyTmpPass2Tmp[0] = new String(new char[keyTmpPass2Tmp[0].length()]);
							keyTmpPass2Tmp[0] = null;
							keyTmpPass2Tmp = null;
						}
					}
					
					if (keyTmpPass2 == null || keyTmpPass2.isEmpty()) {
						keyTmpPass1 = new String(new char[keyTmpPass1.length()]);
						keyTmpPass1 = null;
						
						System.exit(0);
					}
				}
			}
			
			if (mode == Cipher.ENCRYPT_MODE && !keyTmpPass1.equals(keyTmpPass2))
				throw new Exception("the key could not be properly confirmed");
			
			key = new String[] { keyTmpPass1 };
			
			keyTmpPass1 = new String(new char[keyTmpPass1.length()]);
			keyTmpPass1 = null;
			
			if (keyTmpPass2 != null) {
				keyTmpPass2 = new String(new char[keyTmpPass2.length()]);
				keyTmpPass2 = null;
			}
		} catch (Exception e) {
			if (!useGraphicInterface) {
				showError("Could not read the key from the system console. Trying again, using a graphic interface...", false);
				return requestKey(mode, true);
			} else {
				String exceptionMessage = e.getMessage();
				
				if (exceptionMessage != null && !exceptionMessage.isEmpty())
					exceptionMessage = " (" + exceptionMessage + ")";
				else
					exceptionMessage = "";
				
				errExit("Could not read the key" + exceptionMessage + ".");
			}
		}
		
		return key;
	}
	
	private static void doEnDeCryptStream(
		InputStream inputStream, OutputStream outputStream, BufferedBlockCipher[] cipherChain
	) throws IOException
	{
		CipherOutputStream cipherOutputStream = new CipherOutputStream(
			outputStream, cipherChain[cipherChain.length - 1]
		);

		for (int index = cipherChain.length - 2; index >= 0; index--)
			cipherOutputStream = new CipherOutputStream(cipherOutputStream, cipherChain[index]);

		int minInputReadLength = cipherChain[cipherChain.length - 1].getBlockSize();
		byte[] input = new byte[minInputReadLength];
		int inputLengthRead;
		
		for (;;) {
			inputLengthRead = inputStream.read(input);

			if (inputLengthRead == -1)
				break;

			cipherOutputStream.write(input, 0, inputLengthRead);
		}
		
		try {
			inputStream.close();
			cipherOutputStream.close();
		} catch (IOException ioException) {}
	}
	
	private static void enDeCrypt(String key, InputStream inputStream, OutputStream outputStream, int mode)
		throws
			IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException,
			SecurityException, IOException
	{
		byte[] keyHash = digest(utf8StringToByteArray(key), "Skein");
		
		key = new String(new char[key.length()]);
		key = null;
		
		int keyHashPassLength = (keyHash.length / 3) - 1;

		byte[]
			keyHashPass1 = new byte[keyHashPassLength],
			keyHashPass2 = new byte[keyHashPassLength],
			keyHashPass3 = new byte[keyHashPassLength];
		
		System.arraycopy(keyHash, 0, keyHashPass1, 0, keyHashPassLength);
		System.arraycopy(keyHash, keyHashPassLength, keyHashPass2, 0, keyHashPassLength);
		System.arraycopy(keyHash, (2 * keyHashPassLength) - 1, keyHashPass3, 0, keyHashPassLength);
		
		for (int i = 0; i < keyHash.length; i++)
			keyHash[i] = Byte.MIN_VALUE;
		
		keyHash = null;
		
		SecretKeySpec
			keyPass1 = new SecretKeySpec(
				digest(keyHashPass1, "Whirlpool"), "Serpent"
			),
			keyPass2 = new SecretKeySpec(
				digest(keyHashPass2, "Skein"), "Threefish-1024"
			),
			keyPass3 = new SecretKeySpec(
				digest(keyHashPass3, "Skein", 256, 256), "Rijndael"
			);

		PaddedBufferedBlockCipher
			cipherPass1 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SerpentEngine()), new PKCS7Padding()),
			cipherPass2 = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024)), new PKCS7Padding()
			),
			cipherPass3 = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RijndaelEngine()), new PKCS7Padding());
		
		byte[][] ivMaterialChain = new byte[][] {
				new byte[cipherPass1.getBlockSize()],
				new byte[cipherPass2.getBlockSize()],
				new byte[cipherPass3.getBlockSize()]
		};
		
		System.arraycopy(digest(keyHashPass3, "Whirlpool"), 0, ivMaterialChain[0], 0, cipherPass1.getBlockSize());
		System.arraycopy(digest(keyHashPass1, "Skein"), 0, ivMaterialChain[1], 0, cipherPass2.getBlockSize());
		System.arraycopy(digest(keyHashPass2, "Whirlpool"), 0, ivMaterialChain[2], 0, cipherPass3.getBlockSize());
		
		IvParameterSpec
			ivPass1 = new IvParameterSpec(ivMaterialChain[0]),
			ivPass2 = new IvParameterSpec(ivMaterialChain[1]),
			ivPass3 = new IvParameterSpec(ivMaterialChain[2]);
		
		for (byte[] ivMaterial : ivMaterialChain) {
			for (int i = 0; i < ivMaterial.length; i++)
				ivMaterial[i] = Byte.MIN_VALUE;
			ivMaterial = null;
		}
		
		ivMaterialChain = null;
		
		cipherPass1.init(
			mode == Cipher.ENCRYPT_MODE, new ParametersWithIV(new KeyParameter(keyPass1.getEncoded()), ivPass1.getIV())
		);
		cipherPass2.init(
			mode == Cipher.ENCRYPT_MODE, new ParametersWithIV(new KeyParameter(keyPass2.getEncoded()), ivPass2.getIV())
		);
		cipherPass3.init(
			mode == Cipher.ENCRYPT_MODE, new ParametersWithIV(new KeyParameter(keyPass3.getEncoded()), ivPass3.getIV())
		);
		
		try {
			doEnDeCryptStream(
				inputStream,
				outputStream,
				mode == Cipher.ENCRYPT_MODE
					? new BufferedBlockCipher[] { cipherPass1, cipherPass2, cipherPass3 }
					: new BufferedBlockCipher[] { cipherPass3, cipherPass2, cipherPass1 }
			);
		} catch (InvalidCipherTextIOException invalidCipherTextIOException) {
			errExit(
				"The key provided for " + (mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption") + " is wrong."
			);
		}
	}
	
	private static void showUsage(boolean exitClean, boolean prependNewLine)
	{
		showMessage(
			"Usage",
			(System.console() != null ? "usage: " : "") +
				"java -jar cryptor.jar ( -e | -d ) [ path(s)_to_input_file(s) ]" +
				" [ -o prefix{regex}suffix ]" +
				"\n" +
				"\t-e\n\t\tencrypt\n" +
				"\t-d\n\t\tdecrypt\n" +
				"\tpath(s)_to_input_file(s)\n\t\tspace separated paths to input files " +
				"(by default using the standard input stream)\n" +
				"\t-o prefix{regex}suffix\n\t\tfor each input file extract the regex part " +
				"(if no regex has been provided, use the entire input file path) " +
				"\n\t\tand prepend/append the provided prefix/suffix (by default using the standard output stream)",
			prependNewLine
		);
		
		System.exit(exitClean ? 0 : 1);
	}
	
	private static void showUsage(boolean exitClean)
	{
		showUsage(exitClean, !exitClean);
	}
	
	private static void showUsage()
	{
		showUsage(true);
	}
	
	public static void main(String[] args)
		throws
			IllegalAccessException, IllegalArgumentException,
			InvocationTargetException, NoSuchMethodException,
			SecurityException, IOException
	{
		if (args == null || args.length == 0)
			showUsage();
		
		int mode = -1;
		LinkedList<String> inputFilePaths = new LinkedList<String>();
		String outputGlob = null;
		
		for (int index = 0; index < args.length; index++)
			if (args[index].equals("-e")) {
				if (mode != -1) {
					showError("The process mode has already been set.");
					showUsage(false);
				}
				
				mode = Cipher.ENCRYPT_MODE;
			} else if (args[index].equals("-d")) {
				if (mode != -1) {
					showError("The process mode has already been set.");
					showUsage(false);
				}
				
				mode = Cipher.DECRYPT_MODE;
			} else if (args[index].equals("-o")) {
				if (args.length < index + 2) {
					showError("The output glob has not been provided.");
					showUsage(false);
				}
				
				if (outputGlob != null) {
					showError("The output glob has already been set.");
					showUsage(false);
				}
				
				if (!Pattern.matches("(?:^|.+?)\\{.*?\\}(?:.+?|$)", args[index + 1]) ||
					Pattern.matches("^\\s*\\{\\}\\s*$", args[index + 1])) {
					showError("The output glob does not have a valid format.");
					showUsage(false);
				}
				
				outputGlob = args[index + 1];
				
				index += 1;
			} else {
				inputFilePaths.add(args[index].trim());
			}
		
		if (inputFilePaths.size() > 1) {
			if (outputGlob == null) {
				showError("The output glob is required when multiple paths have been set to be processed.");
				showUsage(false);
			}
			
			for (String inputFilePath : inputFilePaths)
				if (!Files.isRegularFile(Paths.get(inputFilePath))) {
					showError(String.format("The file path \"%s\" does not correspond to a regular file.", inputFilePath));
					showUsage(false);
				}
		}
		
		LinkedList<InputStream> inputStreams = new LinkedList<InputStream>();
		
		if (inputFilePaths.isEmpty()) {
			inputStreams.add(System.in);
		} else {
			for (String inputFilePath : inputFilePaths)
				try {
					inputStreams.add(new FileInputStream(inputFilePath));
				} catch (IOException ioException) {
					for (InputStream inputStream : inputStreams)
						try {
							inputStream.close();
						} catch (Exception exception) {}
					
					showError(String.format("The file path \"%s\" could not be opened for reading (%s).", inputFilePath, ioException.getMessage()));
					showUsage(false);
				}
		}
		
		String[] key = requestKey(mode);
		
		for (int i = 0; i < inputStreams.size(); i++) {
			if (inputStreams.size() > 1) {
				System.err.println(String.format(
					"%s file \"%s\"...",
					mode == Cipher.ENCRYPT_MODE ? "Encrypting" : "Decrypting",
					inputFilePaths.get(i)
				));
			}
			
			String inputFilePathProxy = null, outputFilePath = null;
			OutputStream outputStream = null;
			
			try {
				if (inputFilePaths.size() < 2 && outputGlob == null) {
					outputStream = System.out;
				} else {
					Matcher matcherForOutputGlob = Pattern.compile("\\{(.+?)\\}").matcher(outputGlob);
					
					if (matcherForOutputGlob.find()) {
						Matcher matcherForInputFilePath =
							Pattern
								.compile("(?:^|.+?)(" + matcherForOutputGlob.group(1) + ")(?:.+?|$)")
								.matcher(inputFilePaths.get(i));
						
						if (matcherForInputFilePath.find()) {
							inputFilePathProxy = matcherForInputFilePath.group(1);
						} else {
							inputFilePathProxy = inputFilePaths.get(i);
						}
					} else {
						inputFilePathProxy = inputFilePaths.get(i);
					}
					
					outputFilePath = outputGlob.replaceAll("\\{.*?\\}", inputFilePathProxy);
					outputStream = new FileOutputStream(outputFilePath);
				}
			} catch (IOException ioException) {
				showError(String.format(
					"The file path \"%s\" could not be opened for writing (%s).", outputFilePath, ioException.getMessage()
				));
				showUsage(false);
			}
			
			enDeCrypt(key[0], inputStreams.get(i), outputStream, mode);
		}
		
		key[0] = new String(new char[key[0].length()]);
		key[0] = null;
		key = null;
	}
}

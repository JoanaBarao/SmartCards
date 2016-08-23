/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.CallbackHandlerProtection;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TSPException;

/**
 * An example for singing a PDF with bouncy castle.
 * A keystore can be created with the java keytool, for example:
 *
 * {@code keytool -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365
 *        -v -keyalg RSA -keystore keystore.p12 }
 *
 * @author Thomas Chojecki
 * @author Vakhtang Koroghlishvili
 * @author John Hewson
 */
public class CreateSignature extends CreateSignatureBase
{

    /**
     * Initialize the signature creator with a keystore and certficate password.
     * @param keystore the pkcs12 keystore containing the signing certificate
     * @param password the password for recovering the key
     * @throws KeyStoreException if the keystore has not been initialized (loaded)
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException if the certificate is not valid as signing time
     */
    public CreateSignature(KeyStore keystore, char[] password, String alias)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException
    {
        // grabs the first alias from the keystore and get the private key. An
        // TODO alternative method or constructor could be used for setting a specific
        // alias that should be used.
        Enumeration<String> aliases = keystore.aliases();
        setPrivateKey((PrivateKey) keystore.getKey(alias, password));
        Certificate cert = keystore.getCertificateChain(alias)[0];
        setCertificate(cert);
        if (cert instanceof X509Certificate)
        {
            // avoid expired certificate
            ((X509Certificate) cert).checkValidity();
        }
    }

    /**
     * Signs the given PDF file. Alters the original file on disk.
     * @param file the PDF file to sign
     * @throws IOException if the file could not be read or written
     */
    public void signDetached(File file) throws IOException
    {
        signDetached(file, file, null);
    }

    /**
     * Signs the given PDF file.
     * @param inFile input PDF file
     * @param outFile output PDF file
     * @throws IOException if the input file could not be read
     */
    public void signDetached(File inFile, File outFile) throws IOException
    {
        signDetached(inFile, outFile, null);
    }

    /**
     * Signs the given PDF file.
     * @param inFile input PDF file
     * @param outFile output PDF file
     * @param tsaClient optional TSA client
     * @throws IOException if the input file could not be read
     */
    public void signDetached(File inFile, File outFile, TSAClient tsaClient) throws IOException
    {
        if (inFile == null || !inFile.exists())
        {
            throw new FileNotFoundException("Document for signing does not exist");
        }

        FileOutputStream fos = new FileOutputStream(outFile);

        // sign
        PDDocument doc = PDDocument.load(inFile);
        signDetached(doc, fos, tsaClient);
        doc.close();
    }

    public void signDetached(PDDocument document, OutputStream output, TSAClient tsaClient)
            throws IOException
    {
        setTsaClient(tsaClient);

        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Joana Barão Vieira");
        signature.setLocation("Porto");
        signature.setReason("Testing");
        // TODO extract the above details from the signing certificate? Reason as a parameter?

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());

        // register signature dictionary and sign interface
        document.addSignature(signature, this);

        // write incremental (only for signing purpose)
        document.saveIncremental(output);
    }

    /**
     * We just extend CMS signed Data
     *
     * @param signedData -Generated CMS signed data
     * @return CMSSignedData - Extended CMS signed data
     */
    @Override
    protected CMSSignedData signTimeStamps(CMSSignedData signedData)
            throws IOException, TSPException
    {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        List<SignerInformation> newSigners = new ArrayList<SignerInformation>();

        for (SignerInformation signer : signerStore.getSigners())
        {
            newSigners.add(signTimeStamp(signer));
        }

        // TODO do we have to return a new store?
        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }

    /**
     * We are extending CMS Signature
     *
     * @param signer information about signer
     * @return information about SignerInformation
     */
    private SignerInformation signTimeStamp(SignerInformation signer)
            throws IOException, TSPException
    {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null)
        {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        byte[] token = getTsaClient().getTimeStampToken(signer.getSignature());
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

        vector.add(signatureTimeStamp);
        Attributes signedAttributes = new Attributes(vector);

        SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(
                signer, new AttributeTable(signedAttributes));

        // TODO can this actually happen?
        if (newSigner == null)
        {
            return signer;
        }

        return newSigner;
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException
    {
        if (args.length < 2)
        {
            usage();
            System.exit(1);
        }

        String tsaUrl = null;
        for(int i = 0; i < args.length; i++)
        {
            if (args[i].equals("-tsa"))
            {
                i++;
                if (i >= args.length)
                {
                    usage();
                }
                tsaUrl = args[i];
            }
        }

        String pkcs11lib="";
        String alias="";
        String extension="";
        if ((args[1]).equals("1")) {
        	pkcs11lib = "/usr/lib/pkcs11/opensc-pkcs11.so";
        	alias = "SignatureCert";
        	extension = "_signed_SmartCard.pdf";
        }
        else if ((args[1]).equals("2")) {
        	pkcs11lib = "/usr/local/lib/libpteidpkcs11.so";
        	alias="CITIZEN SIGNATURE CERTIFICATE";
        	extension = "_signed_CC.pdf";
        }
        else {
        	usage();
            System.exit(1);
        }
        	
        
        // Keystore
        String pkcs11ConfigSettings = "name=Signature\n" + "library=" + pkcs11lib +"\nslotListIndex=0\n";
        byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
        final ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);
       	Provider p = new sun.security.pkcs11.SunPKCS11(confStream);
       	Security.addProvider(p);
       	
       	CallbackHandler passwordCallbackHandler = new SwingPasswordCallbackHandler();
       	CallbackHandlerProtection pwCallbackProt = new CallbackHandlerProtection(passwordCallbackHandler);
       	KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", p, pwCallbackProt);
       	KeyStore ks = builder.getKeyStore();
        
       	// TSA client
        TSAClient tsaClient = null;
        if (tsaUrl != null)
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            tsaClient = new TSAClient(new URL(tsaUrl), null, null, digest);
        }

        // sign PDF
        CreateSignature signing = new CreateSignature(ks, null, alias);
        File inFile = new File(args[0]);
        String name = inFile.getName();
        String substring = name.substring(0, name.lastIndexOf('.'));

        File outFile = new File(inFile.getParent(), substring + extension);
        signing.signDetached(inFile, outFile, tsaClient);
    }

    private static void usage()
    {
        System.err.println("usage: java " + CreateSignature.class.getName() + " " +
                           "<pdf_to_sign> <Type_of_Signature>\n" +
                           "Type of Signature:\n" +
                           "  1 - SmartCard Signature\n" +
                           "  2 - Cartão de Cidadão Signature\n" +
                           "  -tsa <url>    sign timestamp using the given TSA server");
    }
}

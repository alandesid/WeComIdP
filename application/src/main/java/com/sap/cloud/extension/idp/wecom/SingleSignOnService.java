package com.sap.cloud.extension.idp.wecom;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.axis2.databinding.types.xsd.DateTime;
import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.extension.idp.utils.IdPConstants;
import com.sap.cloud.extension.idp.utils.IdPCredentials;
import com.sap.cloud.extension.idp.utils.OpenSAMLUtils;
import com.sap.cloud.extension.idp.utils.SPConstants;
import com.sap.cloud.extension.idp.utils.SPCredentials;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;


/**
 * Servlet implementation class SingleSignOnService
 */
@WebServlet("/saml2/idp/SingleSignOnService")
public class SingleSignOnService extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final Logger logger = LoggerFactory.getLogger(SingleSignOnService.class); 
	private ServletConfig config;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public SingleSignOnService() {
        super();
        // TODO Auto-generated constructor stub
    }
    
    public void init(ServletConfig config) throws ServletException {
        this.config = config;
        this.init();
		JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
		try {
			javaCryptoValidationInitializer.init();

			for (Provider jceProvider : Security.getProviders()) {
				logger.info(jceProvider.getInfo());
			}

			XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
			ConfigurationService.register(XMLObjectProviderRegistry.class, registry);

			registry.setParserPool(getParserPool());

			logger.info("Initializing");
			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new RuntimeException("Initialization failed");
		}
    }
    
	private static ParserPool getParserPool() {
		BasicParserPool parserPool = new BasicParserPool();
		parserPool.setMaxPoolSize(100);
		parserPool.setCoalescing(true);
		parserPool.setIgnoreComments(true);
		parserPool.setIgnoreElementContentWhitespace(true);
		parserPool.setNamespaceAware(true);
		parserPool.setExpandEntityReferences(false);
		parserPool.setXincludeAware(false);

		final Map<String, Boolean> features = new HashMap<String, Boolean>();
		features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
		features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
		features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
		features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
		features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);

		parserPool.setBuilderFeatures(features);

		parserPool.setBuilderAttributes(new HashMap<String, Object>());

		try {
			parserPool.initialize();
		} catch (ComponentInitializationException e) {
			logger.error(e.getMessage(), e);
		}

		return parserPool;
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		Response samlResponse = buildResponse();
		String samlResponseString = OpenSAMLUtils.transSAMLObject2String(samlResponse);
		String encodedString = Base64.getEncoder().encodeToString(samlResponseString.getBytes());
		request.setAttribute("ACService", "https://agm5kinb9.accounts.sapcloud.cn/saml2/idp/acs/agm5kinb9.accounts.sapcloud.cn");
		request.setAttribute("SAMLResponse", encodedString);
		request.getRequestDispatcher("/idp_post_binding.jsp").forward(request, response);
		//response.getWriter().append("Served at: ").append(samlResponse.toString());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}
	
	private Response buildResponse() {

		Response response = OpenSAMLUtils.buildSAMLObject(Response.class);
		response.setDestination(SPConstants.ASSERTION_CONSUMER_SERVICE);
		response.setIssueInstant(Instant.now());
		response.setID(OpenSAMLUtils.generateSecureRandomId());
		Issuer issuer2 = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer2.setValue(IdPConstants.IDP_ENTITY_ID);

		response.setIssuer(issuer2);

		Status status2 = OpenSAMLUtils.buildSAMLObject(Status.class);
		StatusCode statusCode2 = OpenSAMLUtils.buildSAMLObject(StatusCode.class);
		statusCode2.setValue(StatusCode.SUCCESS);
		status2.setStatusCode(statusCode2);

		response.setStatus(status2);
		Assertion assertion = buildAssertion();
		response.getAssertions().add(assertion);
		signAssertion(assertion);
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);
		response.getEncryptedAssertions().add(encryptedAssertion);
		
		return response;
	}

	private EncryptedAssertion encryptAssertion(Assertion assertion) {
		DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
		encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(SPCredentials.getCredential());
		keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

		Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
		encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

		try {
			EncryptedAssertion encryptedAssertion = encrypter.encrypt(assertion);
			return encryptedAssertion;
		} catch (EncryptionException e) {
			throw new RuntimeException(e);
		}
	}

	private void signAssertion(Assertion assertion) {
		Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
		signature.setSigningCredential(IdPCredentials.getCredential());
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		assertion.setSignature(signature);

		try {
			XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
		} catch (MarshallingException e) {
			throw new RuntimeException(e);
		}

		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	private Assertion buildAssertion() {

		Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);

		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
		issuer.setValue(IdPConstants.IDP_ENTITY_ID);
		assertion.setIssuer(issuer);
		assertion.setIssueInstant(Instant.now());

		assertion.setID(OpenSAMLUtils.generateSecureRandomId());

		Subject subject = OpenSAMLUtils.buildSAMLObject(Subject.class);
		assertion.setSubject(subject);

		NameID nameID = OpenSAMLUtils.buildSAMLObject(NameID.class);
		nameID.setFormat(NameIDType.TRANSIENT);
		nameID.setValue("Some NameID value");
		nameID.setSPNameQualifier("SP name qualifier");
		nameID.setNameQualifier("Name qualifier");

		subject.setNameID(nameID);

		subject.getSubjectConfirmations().add(buildSubjectConfirmation());

		assertion.setConditions(buildConditions());

		assertion.getAttributeStatements().add(buildAttributeStatement());

		assertion.getAuthnStatements().add(buildAuthnStatement());

		return assertion;
	}

	private SubjectConfirmation buildSubjectConfirmation() {
		SubjectConfirmation subjectConfirmation = OpenSAMLUtils.buildSAMLObject(SubjectConfirmation.class);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

		SubjectConfirmationData subjectConfirmationData = OpenSAMLUtils.buildSAMLObject(SubjectConfirmationData.class);
		subjectConfirmationData.setInResponseTo("Made up ID");
		subjectConfirmationData.setNotBefore(Instant.now());
		subjectConfirmationData.setNotOnOrAfter(Instant.now().plus(10, ChronoUnit.MINUTES));
		subjectConfirmationData.setRecipient(SPConstants.ASSERTION_CONSUMER_SERVICE);

		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

		return subjectConfirmation;
	}

	private AuthnStatement buildAuthnStatement() {
		AuthnStatement authnStatement = OpenSAMLUtils.buildSAMLObject(AuthnStatement.class);
		AuthnContext authnContext = OpenSAMLUtils.buildSAMLObject(AuthnContext.class);
		AuthnContextClassRef authnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
		authnContextClassRef.setURI(AuthnContext.SMARTCARD_AUTHN_CTX);
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnStatement.setAuthnContext(authnContext);

		authnStatement.setAuthnInstant(Instant.now());

		return authnStatement;
	}

	private Conditions buildConditions() {
		Conditions conditions = OpenSAMLUtils.buildSAMLObject(Conditions.class);
		conditions.setNotBefore(Instant.now());
		conditions.setNotOnOrAfter(Instant.now().plus(10, ChronoUnit.MINUTES));
		AudienceRestriction audienceRestriction = OpenSAMLUtils.buildSAMLObject(AudienceRestriction.class);
		Audience audience = OpenSAMLUtils.buildSAMLObject(Audience.class);
		audience.setURI(SPConstants.ASSERTION_CONSUMER_SERVICE);
		audienceRestriction.getAudiences().add(audience);
		conditions.getAudienceRestrictions().add(audienceRestriction);
		return conditions;
	}

	private AttributeStatement buildAttributeStatement() {
		AttributeStatement attributeStatement = OpenSAMLUtils.buildSAMLObject(AttributeStatement.class);

		Attribute attributeUserName = OpenSAMLUtils.buildSAMLObject(Attribute.class);

		XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);
		XSString userNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		userNameValue.setValue("bob");

		attributeUserName.getAttributeValues().add(userNameValue);
		attributeUserName.setName("username");
		attributeStatement.getAttributes().add(attributeUserName);

		Attribute attributeLevel = OpenSAMLUtils.buildSAMLObject(Attribute.class);
		XSString levelValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		levelValue.setValue("999999999");

		attributeLevel.getAttributeValues().add(levelValue);
		attributeLevel.setName("telephone");
		attributeStatement.getAttributes().add(attributeLevel);

		return attributeStatement;

	}

}

package org.ops.saml.test;

import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Date;
import java.util.UUID;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import javax.xml.namespace.QName;

import static org.mockito.Mockito.*;
import org.springframework.mock.web.MockHttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;

import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;

import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Scoping;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.SessionIndex;

import org.opensaml.saml2.core.Condition;
import org.opensaml.saml2.core.IDPList;
import org.opensaml.saml2.core.IDPEntry;

import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.OneTimeUse;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Response;

import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml2.core.impl.ResponseMarshaller;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;

import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;

//import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoGenerator;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;;


import org.w3c.dom.*;
import org.w3c.dom.Element;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    DateTime now;
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
        now = new DateTime();
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {

        try {
            DefaultBootstrap.bootstrap();
        }catch (org.opensaml.xml.ConfigurationException e) {
            System.out.println("Exception: " + e.toString());
        } 
        
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp()
    {
      List mockedList = mock(List.class);
      mockedList.add("one");
      mockedList.clear();

      verify(mockedList).add("one");
      verify(mockedList).clear();
    }

     /**
      * Rigourous Test :-)
      */
     public void testCreateSAMLRequest()
     {
       // Get the builder factory
       XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        
       // Get the assertion builder based on the assertion element name
       SAMLObjectBuilder<Assertion> builder = (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        
       // Create the assertion
       Assertion assertion = builder.buildObject();

       System.out.println("assertion: " + assertion.toString());
       assertTrue(true);
     }

     private XMLObject buildObject(QName objectQName)
     {
       XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(objectQName);
       if (builder != null) {
         return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix()); 
       } else {
         return null;
       }
     }

  public void testRequest() throws java.lang.Exception
  {
    MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    AuthnRequest authnRequest = buildAuthnRequest();
    //authnRequest.setIsPassive(true);
    authnRequest.setAssertionConsumerServiceURL("https://sp.htc.com/saml2/response");
    authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

    // Signature
    Signature signature = (Signature) buildObject(Signature.DEFAULT_ELEMENT_NAME);

    // .. generate key-pair for signing
    KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // .. generate credential
    Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

    signature.setSigningCredential(credential);
    authnRequest.setSignature(signature);

    SecurityHelper.prepareSignatureParams(signature, credential, null, null);
    Element element = marshallerFactory.getMarshaller(authnRequest).marshall(authnRequest);
    String unsignedAuthnRequestString = XMLHelper.nodeToString(element);

	  Signer.signObject(signature);
    String originalAuthnRequestString = XMLHelper.nodeToString(element);

	  System.out.println("Unsigned AuthnRequest: " + unsignedAuthnRequestString);
    System.out.println("AuthnRequest String: " + originalAuthnRequestString);

    assertTrue(true);
  }

  public void testRequestBinding_Redirect() throws Exception
  {
    AuthnRequest authnRequest = buildAuthnRequest();
    //authnRequest.setIsPassive(true);
    authnRequest.setAssertionConsumerServiceURL("https://sp.htc.com/saml2/response");
    authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("https://account.htc.com/service/saml2/authnRequest");
	  samlEndpoint.setResponseLocation("https://sp.htc.com/saml2/");

    MockHttpServletResponse response = new MockHttpServletResponse();
	  HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

	  BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	  messageContext.setOutboundMessageTransport(outTransport);
	  messageContext.setOutboundSAMLMessage(authnRequest);
	  messageContext.setPeerEntityEndpoint(samlEndpoint);
	  messageContext.setRelayState("relay");

    // generate key-pair for signing
    KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // generate credential
    Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

	  messageContext.setOutboundSAMLMessageSigningCredential(credential);

	  HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	  encoder.encode(messageContext);

	  System.out.println("AuthRequest Redirect-binding: " + response.getRedirectedUrl());

	  String queryString = new URL(response.getRedirectedUrl()).getQuery();
	  assertNotNull("Signature parameter was not found",
	    HTTPTransportUtils.getRawQueryStringParameter(queryString, "Signature"));
	  assertNotNull("SigAlg parameter was not found",
	    HTTPTransportUtils.getRawQueryStringParameter(queryString, "SigAlg"));
  }

  public void testAssertion()
  {
    Assertion assertion = buildAssertion();

    try {
      AssertionMarshaller marshaller = new AssertionMarshaller();
      Element plaintextElement = marshaller.marshall(assertion);
      String originalAssertionString = XMLHelper.nodeToString(plaintextElement);
      System.out.println("Assertion: " + originalAssertionString);
    } catch (MarshallingException e) {
      System.out.println("Exception: " + e.toString());
    }

    StatusCode statusCode = (StatusCode) buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
    statusCode.setValue(StatusCode.SUCCESS_URI); 

    Status status = (Status) buildObject(Status.DEFAULT_ELEMENT_NAME);
    status.setStatusCode(statusCode);
    
    Response response = (Response) buildObject(Response.DEFAULT_ELEMENT_NAME);
    response.setVersion(SAMLVersion.VERSION_20);
    response.setID(UUID.randomUUID().toString());
    response.setIssueInstant(now);
    
    response.setStatus(status);
    response.getAssertions().add(assertion);

    try {
      ResponseMarshaller marshaller = new ResponseMarshaller();
      Element plaintextElement = marshaller.marshall(response);
      String serialized = XMLHelper.nodeToString(plaintextElement);
      System.out.println("Response: " + serialized);
    } catch (MarshallingException e) {
      System.out.println("Exception: " + e.toString());
    }

    assertTrue(true);
  }

  public void testAssertion_Redirect() throws Exception
  {
    Response samlResponse = buildResponse();

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("https://sp.htc.com/saml2/response");
	  samlEndpoint.setResponseLocation("https://account.htc.com/service/saml2/");

    MockHttpServletResponse response = new MockHttpServletResponse();
	  HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

	  BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	  messageContext.setOutboundMessageTransport(outTransport);
	  messageContext.setOutboundSAMLMessage(samlResponse);
	  messageContext.setPeerEntityEndpoint(samlEndpoint);
	  messageContext.setRelayState("relay");

    // generate key-pair for signing
    KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // generate credential
    Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

	  messageContext.setOutboundSAMLMessageSigningCredential(credential);

	  HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	  encoder.encode(messageContext);

	  System.out.println("Assertion Redirect-binding: " + response.getRedirectedUrl());

	  String queryString = new URL(response.getRedirectedUrl()).getQuery();
	  assertNotNull("Signature parameter was not found",
	    HTTPTransportUtils.getRawQueryStringParameter(queryString, "Signature"));
	  assertNotNull("SigAlg parameter was not found",
	    HTTPTransportUtils.getRawQueryStringParameter(queryString, "SigAlg"));
  }

  public void testEncryptedAssertion_RedirectBinding() throws Exception
  {
    Response samlResponse = buildResponseWithEncryptedAssertion();

    //{
    //  ResponseMarshaller marshaller = new ResponseMarshaller();
    //  Element plaintextElement = marshaller.marshall(samlResponse);
    //  String serialized = XMLHelper.nodeToString(plaintextElement);
    //  System.out.println("Assertion Response String: " + serialized);
    //}

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("https://sp.htc.com/saml2/response");
	  samlEndpoint.setResponseLocation("https://account.htc.com/service/saml2/");

    MockHttpServletResponse response = new MockHttpServletResponse();
	  HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

	  BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	  messageContext.setOutboundMessageTransport(outTransport);
	  messageContext.setOutboundSAMLMessage(samlResponse);
	  messageContext.setPeerEntityEndpoint(samlEndpoint);
	  messageContext.setRelayState("relay");

    // generate key-pair for signing
    KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // generate credential
    Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

	  messageContext.setOutboundSAMLMessageSigningCredential(credential);

	  HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	  encoder.encode(messageContext);

	  System.out.println("Response Redirect-binding: " + response.getRedirectedUrl());

	  String queryString = new URL(response.getRedirectedUrl()).getQuery();
	  assertNotNull("Signature parameter was not found",
	    HTTPTransportUtils.getRawQueryStringParameter(queryString, "Signature"));
	  assertNotNull("SigAlg parameter was not found",
	    HTTPTransportUtils.getRawQueryStringParameter(queryString, "SigAlg"));
  }

  public void testEncryptedAssertion_PostBinding() throws Exception
  {
    Response samlResponse = buildResponseWithEncryptedAssertion();

    //{
    //  ResponseMarshaller marshaller = new ResponseMarshaller();
    //  Element plaintextElement = marshaller.marshall(samlResponse);
    //  String serialized = XMLHelper.nodeToString(plaintextElement);
    //  System.out.println("Assertion Response String: " + serialized);
    //}

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("https://sp.htc.com/saml2/response");
	  samlEndpoint.setResponseLocation("https://account.htc.com/service/saml2/");

    MockHttpServletResponse response = new MockHttpServletResponse();
	  HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

	  BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	  messageContext.setOutboundMessageTransport(outTransport);
	  messageContext.setOutboundSAMLMessage(samlResponse);
	  messageContext.setPeerEntityEndpoint(samlEndpoint);
	  messageContext.setRelayState("relay");

    // generate key-pair for signing
    KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // generate credential
    Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

	  messageContext.setOutboundSAMLMessageSigningCredential(credential);

    // template engine
    VelocityEngine velocityEngine = new VelocityEngine();
    velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
    velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
    velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
    velocityEngine.setProperty("classpath.resource.loader.class","org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
    velocityEngine.init();
    
    HTTPPostSimpleSignEncoder encoder = new HTTPPostSimpleSignEncoder(velocityEngine,"/templates/saml2-post-simplesign-binding.vm");
    encoder.encode(messageContext);

    String form = response.getContentAsString();
	  System.out.println("Response Post-binding: " + form);

    int start = 0;
    start = form.indexOf("name=\"Signature\"");
    assertTrue("Signature parameter not found in form control data", start != -1);
  }

  public void testLogoutRequest_Redirect() throws Exception
  {
    MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    LogoutRequest samlRequest = buildLogoutRequest();

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("https://account.htc.com/service/saml2/logoutRequest");
	  samlEndpoint.setResponseLocation("https://sp.htc.com/saml2/logoutResponse");

    MockHttpServletResponse response = new MockHttpServletResponse();
	  HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

	  BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	  messageContext.setOutboundMessageTransport(outTransport);
	  messageContext.setOutboundSAMLMessage(samlRequest);
	  messageContext.setPeerEntityEndpoint(samlEndpoint);
	  messageContext.setRelayState("relay");

    // generate key-pair for signing
    KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // generate credential
    Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

	  messageContext.setOutboundSAMLMessageSigningCredential(credential);

	  HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	  encoder.encode(messageContext);

	  System.out.println("LogoutRequest Redirect-binding: " + response.getRedirectedUrl());

	  String queryString = new URL(response.getRedirectedUrl()).getQuery();
	  assertNotNull("Signature parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "Signature"));
	  assertNotNull("SigAlg parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "SigAlg"));
  }

  public void testLogoutResponse_Redirect() throws Exception
  {
    MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    LogoutResponse samlResponse = buildLogoutResponse();

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("https://sp.htc.com/saml2/logoutResponse");
	  samlEndpoint.setResponseLocation("https://account.htc.com/service/saml2/");

    MockHttpServletResponse response = new MockHttpServletResponse();
	  HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

	  BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	  messageContext.setOutboundMessageTransport(outTransport);
	  messageContext.setOutboundSAMLMessage(samlResponse);
	  messageContext.setPeerEntityEndpoint(samlEndpoint);
	  messageContext.setRelayState("relay");

    // generate key-pair for signing
    KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // generate credential
    Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

	  messageContext.setOutboundSAMLMessageSigningCredential(credential);

	  HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	  encoder.encode(messageContext);

	  System.out.println("LogoutResponse Redirect-binding: " + response.getRedirectedUrl());

	  String queryString = new URL(response.getRedirectedUrl()).getQuery();
	  assertNotNull("Signature parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "Signature"));
	  assertNotNull("SigAlg parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "SigAlg"));
  }

  private AuthnRequest buildAuthnRequest()
  {
    String messageId = "eb8b724e-6b88-4721-95e1-032cd6243725";

    // AuthnRequest
    AuthnRequest authnRequest = (AuthnRequest) buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);

    // Scoping
    Scoping scoping = (Scoping) buildObject(Scoping.DEFAULT_ELEMENT_NAME);

    // .. IDPList
    IDPList idpList = (IDPList) buildObject(IDPList.DEFAULT_ELEMENT_NAME);
    
    // .. IDPEntry
	  IDPEntry idpEntry = (IDPEntry) buildObject(IDPEntry.DEFAULT_ELEMENT_NAME);
    idpEntry.setName("account.htc.com");
    idpEntry.setProviderID("account.htc.com");

    idpList.getIDPEntrys().add(idpEntry);
    scoping.setIDPList(idpList);
      
    // Issuer
    Issuer issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("https://sp.htc.com/saml2/");
	
    authnRequest.setID(messageId);
    authnRequest.setVersion(SAMLVersion.VERSION_20);
    authnRequest.setIssuer(issuer);
    authnRequest.setProviderName("sp.htc.com");
    authnRequest.setScoping(scoping);

    return authnRequest;
  }

  private Response buildResponseWithEncryptedAssertion() throws Exception
  {
    String inResponseTo = "eb8b724e-6b88-4721-95e1-032cd6243725";
    String messageId = UUID.randomUUID().toString();

    Assertion assertion = buildAssertion();

    KeyName keyName = (KeyName) buildObject(KeyName.DEFAULT_ELEMENT_NAME);
    keyName.setValue("KeyName");

    KeyInfo keyInfo = (KeyInfo) buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
    keyInfo.getKeyNames().add(keyName);

    Credential credentialAES;
    credentialAES = SecurityHelper.generateKeyAndCredential(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
    EncryptionParameters encParams = new EncryptionParameters();
    encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
    encParams.setEncryptionCredential(credentialAES);

    Credential keyCredentialRSA;
    keyCredentialRSA = SecurityHelper.generateKeyPairAndCredential(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP, 2048, false);
    KeyEncryptionParameters keyEncParams = new KeyEncryptionParameters();
    keyEncParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
    keyEncParams.setEncryptionCredential(keyCredentialRSA);
    keyEncParams.setKeyInfoGenerator(new StaticKeyInfoGenerator(keyInfo));

    ArrayList<KeyEncryptionParameters> keyEncParamsList = new ArrayList<KeyEncryptionParameters>();
    keyEncParamsList.add(keyEncParams);

    Encrypter encrypter = new Encrypter(encParams, keyEncParamsList);
    encrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

    EncryptedAssertion encedAssertion = null;
    try {
      encedAssertion = encrypter.encrypt(assertion);
    }
    catch (EncryptionException e)
    {
      System.out.println("Encryption failed, " + e);
    }

    StatusCode statusCode = (StatusCode) buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
    statusCode.setValue(StatusCode.SUCCESS_URI); 

    Status status = (Status) buildObject(Status.DEFAULT_ELEMENT_NAME);
    status.setStatusCode(statusCode);

    // Issuer
    Issuer issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("https://account.htc.com/service/saml2/");

    Response response = (Response) buildObject(Response.DEFAULT_ELEMENT_NAME);
    response.setID(messageId);
    response.setVersion(SAMLVersion.VERSION_20);
    response.setIssuer(issuer);
    response.setIssueInstant(now);
    response.setInResponseTo(inResponseTo);
       
    response.setStatus(status);
    response.getEncryptedAssertions().add(encedAssertion);

    return response;
  }

  private Response buildResponse()
  {
    String inResponseTo = "eb8b724e-6b88-4721-95e1-032cd6243725";
    String messageId = UUID.randomUUID().toString();

    Assertion assertion = buildAssertion();

    StatusCode statusCode = (StatusCode) buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
    statusCode.setValue(StatusCode.SUCCESS_URI); 

    Status status = (Status) buildObject(Status.DEFAULT_ELEMENT_NAME);
    status.setStatusCode(statusCode);

    // Issuer
    Issuer issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("https://account.htc.com/service/saml2/");

    Response response = (Response) buildObject(Response.DEFAULT_ELEMENT_NAME);
    response.setID(messageId);
    response.setVersion(SAMLVersion.VERSION_20);
    response.setIssuer(issuer);
    response.setIssueInstant(now);
    response.setInResponseTo(inResponseTo);
       
    response.setStatus(status);
    response.getAssertions().add(assertion);

    return response;
  }

  private Assertion buildAssertion()
  {
    String assertionId = UUID.randomUUID().toString();
    String accountId = UUID.randomUUID().toString();

    XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    // NameIdentifier
    NameID nameId = (NameID) buildObject(NameID.DEFAULT_ELEMENT_NAME);
    nameId.setValue(accountId);
    nameId.setNameQualifier("account.htc.com");
    nameId.setFormat(NameID.UNSPECIFIED);

    // SubjectConfirmation
    SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
    confirmationMethod.setNotBefore(now);
    confirmationMethod.setNotOnOrAfter(now.plusMinutes(1));

    SubjectConfirmation subjectConfirmation = (SubjectConfirmation) buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
    subjectConfirmation.setSubjectConfirmationData(confirmationMethod);

    // Subject
    Subject subject = (Subject) buildObject(Subject.DEFAULT_ELEMENT_NAME);
    subject.setNameID(nameId);
    subject.getSubjectConfirmations().add(subjectConfirmation);

    // Authentication Statement
    AuthnStatement authnStatement = (AuthnStatement) buildObject(AuthnStatement.DEFAULT_ELEMENT_NAME);

    // .. Authentication Context
    AuthnContext authnContext = (AuthnContext) buildObject(AuthnContext.DEFAULT_ELEMENT_NAME);

	  // .. .. Authentication Context Class
    AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

    authnContext.setAuthnContextClassRef(authnContextClassRef);

    authnStatement.setAuthnInstant(now);
    authnStatement.setSessionIndex(UUID.randomUUID().toString());
    authnStatement.setSessionNotOnOrAfter(now.plus(60));
    authnStatement.setAuthnContext(authnContext);

    // Attributes Statement
    AttributeStatement attrStatement = (AttributeStatement) buildObject(AttributeStatement.DEFAULT_ELEMENT_NAME);

    SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
    XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);

    // .. EmailAddress
    {
      Attribute attr = (Attribute) attrBuilder.buildObject();
      attr.setName("EmailAddress");

      XSString value = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
      value.setValue("alice_smith@mail.server");

      attr.getAttributeValues().add(value);
      attrStatement.getAttributes().add(attr);
    }

    // .. FirstName
    {
      Attribute attr = (Attribute) attrBuilder.buildObject();
      attr.setName("FirstName");

      XSString value = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
      value.setValue("Alice");

      attr.getAttributeValues().add(value);
      attrStatement.getAttributes().add(attr);
    }

    // .. LastName
    {
      Attribute attr = (Attribute) attrBuilder.buildObject();
      attr.setName("LastName");

      XSString value = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
      value.setValue("Smith");

      attr.getAttributeValues().add(value);
      attrStatement.getAttributes().add(attr);
    }
    
    // .. Country
    {
      Attribute attr = (Attribute) attrBuilder.buildObject();
      attr.setName("Country");

      XSString value = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
      value.setValue("US");

      attr.getAttributeValues().add(value);
      attrStatement.getAttributes().add(attr);
    }
    
    // .. Language
    {
      Attribute attr = (Attribute) attrBuilder.buildObject();
      attr.setName("Language");

      XSString value = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
      value.setValue("en_US");

      attr.getAttributeValues().add(value);
      attrStatement.getAttributes().add(attr);
    }
    
    // Conditions
    Conditions conditions = (Conditions) buildObject(Conditions.DEFAULT_ELEMENT_NAME);
 
    // .. do-not-cache
    Condition condition = (Condition) buildObject(OneTimeUse.DEFAULT_ELEMENT_NAME);

    conditions.getConditions().add(condition);
    
    // Issuer
    Issuer issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("https://account.htc.com/service/saml2/");

    // Assertion
    Assertion assertion = (Assertion) buildObject(Assertion.DEFAULT_ELEMENT_NAME);
    assertion.setVersion(SAMLVersion.VERSION_20);
    assertion.setID(assertionId);
    assertion.setIssueInstant(now);

    assertion.setSubject(subject);
    assertion.setIssuer(issuer);
    assertion.getAuthnStatements().add(authnStatement);
    assertion.getAttributeStatements().add(attrStatement);
    assertion.setConditions(conditions);

    return assertion;
  }

  private LogoutRequest buildLogoutRequest()
  {
    String accountId = UUID.randomUUID().toString();
    String sessionId = UUID.randomUUID().toString();

    LogoutRequest logoutRequest = (LogoutRequest) buildObject(LogoutRequest.DEFAULT_ELEMENT_NAME);

    logoutRequest.setID(UUID.randomUUID().toString());
    logoutRequest.setVersion(SAMLVersion.VERSION_20);
    logoutRequest.setIssueInstant(now);

    // Issuer
    Issuer issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("https://service-provider/saml2/");

    // NameIdentifier
    NameID nameId = (NameID) buildObject(NameID.DEFAULT_ELEMENT_NAME);
    nameId.setValue(accountId);
    nameId.setNameQualifier("account.htc.com");
    nameId.setFormat(NameID.UNSPECIFIED);

    // SessionIndex
    SessionIndex sessionIndex = (SessionIndex) buildObject(SessionIndex.DEFAULT_ELEMENT_NAME);
    sessionIndex.setSessionIndex(sessionId);

    logoutRequest.setIssuer(issuer);
    logoutRequest.setNotOnOrAfter(now.plusMinutes(1));
    logoutRequest.setReason("urn:string:reason");
    logoutRequest.setNameID(nameId);
    logoutRequest.getSessionIndexes().add(sessionIndex);

    return logoutRequest;
  }


  private LogoutResponse buildLogoutResponse()
  {
    String inResponseTo = "dd07c418-d970-4023-a461-4086d6ee663c";
    String messageId = UUID.randomUUID().toString();

    // Issuer
    Issuer issuer = (Issuer) buildObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("https://account.htc.com/service/saml2/");

    // Status
    StatusCode statusCode = (StatusCode) buildObject(StatusCode.DEFAULT_ELEMENT_NAME);
    statusCode.setValue(StatusCode.SUCCESS_URI); 

    Status status = (Status) buildObject(Status.DEFAULT_ELEMENT_NAME);
    status.setStatusCode(statusCode);

    LogoutResponse logoutResponse = (LogoutResponse) buildObject(LogoutResponse.DEFAULT_ELEMENT_NAME);

    logoutResponse.setID(messageId);
    logoutResponse.setVersion(SAMLVersion.VERSION_20);
    logoutResponse.setIssueInstant(now);
    logoutResponse.setInResponseTo(inResponseTo);
    logoutResponse.setIssuer(issuer);
    logoutResponse.setStatus(status);

    return logoutResponse;
  }


}

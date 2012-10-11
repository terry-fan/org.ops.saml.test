package org.ops.saml.test;

import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Date;
import java.util.UUID;
import java.net.URL;
import java.security.KeyPair;

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

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Scoping;

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
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;


import org.w3c.dom.*;
import org.w3c.dom.Element;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
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
          DateTime now = new DateTime();

          MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

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
          issuer.setValue("https://account.htc.com/service/saml2/");
	 
          authnRequest.setID(UUID.randomUUID().toString());
          authnRequest.setVersion(SAMLVersion.VERSION_20);
          authnRequest.setIssuer(issuer);
          authnRequest.setIsPassive(true);
          authnRequest.setProviderName("support.htc.com");
          authnRequest.setScoping(scoping);
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
          DateTime now = new DateTime();

          MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

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
          issuer.setValue("https://account.htc.com/service/saml2/");
	 
          authnRequest.setID(UUID.randomUUID().toString());
          authnRequest.setVersion(SAMLVersion.VERSION_20);
          authnRequest.setIssuer(issuer);
          authnRequest.setIsPassive(true);
          authnRequest.setProviderName("support.htc.com");
          authnRequest.setScoping(scoping);
          authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("http://example.org");
	  samlEndpoint.setResponseLocation("http://example.org/response");

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

	  String queryString = new URL(response.getRedirectedUrl()).getQuery();

	  System.out.println("Redirect-binding: " + queryString);

	  assertNotNull("Signature parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "Signature"));
	  assertNotNull("SigAlg parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "SigAlg"));
     }

     public void testAssertion()
     {
          String assertionId = UUID.randomUUID().toString();
          String accountId = UUID.randomUUID().toString();
          DateTime now = new DateTime();

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


          try {
            AssertionMarshaller marshaller = new AssertionMarshaller();
            Element plaintextElement = marshaller.marshall(assertion);
            String originalAssertionString = XMLHelper.nodeToString(plaintextElement);
            System.out.println("Assertion String: " + originalAssertionString);
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
            System.out.println("Assertion Response String: " + serialized);
          } catch (MarshallingException e) {
            System.out.println("Exception: " + e.toString());
          }

          assertTrue(true);
     }

     public void testAssertion_Redirect() throws Exception
     {
          String assertionId = UUID.randomUUID().toString();
          String accountId = UUID.randomUUID().toString();
          DateTime now = new DateTime();

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

	  {
            AssertionMarshaller marshaller = new AssertionMarshaller();
            Element plaintextElement = marshaller.marshall(assertion);
            String originalAssertionString = XMLHelper.nodeToString(plaintextElement);
            System.out.println("Assertion String: " + originalAssertionString);
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

	  {
            ResponseMarshaller marshaller = new ResponseMarshaller();
            Element plaintextElement = marshaller.marshall(response);
            String serialized = XMLHelper.nodeToString(plaintextElement);
            System.out.println("Assertion Response String: " + serialized);
	  }

	  Endpoint samlEndpoint = (Endpoint) buildObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	  samlEndpoint.setLocation("http://example.org");
	  samlEndpoint.setResponseLocation("http://example.org/response");

          MockHttpServletResponse samlp_response = new MockHttpServletResponse();
	  HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(samlp_response, false);

	  BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	  messageContext.setOutboundMessageTransport(outTransport);
	  messageContext.setOutboundSAMLMessage(response);
	  messageContext.setPeerEntityEndpoint(samlEndpoint);
	  messageContext.setRelayState("relay");

          // generate key-pair for signing
          KeyPair keyPair = SecurityTestHelper.generateKeyPair("RSA", 2048, null);

	  // generate credential
          Credential credential = SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());

	  messageContext.setOutboundSAMLMessageSigningCredential(credential);

	  HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	  encoder.encode(messageContext);

	  String queryString = new URL(samlp_response.getRedirectedUrl()).getQuery();

	  System.out.println("Redirect-binding: " + queryString);

	  assertNotNull("Signature parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "Signature"));
	  assertNotNull("SigAlg parameter was not found",
	      HTTPTransportUtils.getRawQueryStringParameter(queryString, "SigAlg"));
     }

}

package org.ops.saml.test;

import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Date;
import java.util.UUID;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import static org.mockito.Mockito.*;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
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
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;

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

     public void testRequest()
     {
          DateTime now = new DateTime();

          XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

          // AuthnRequest
          SAMLObjectBuilder<AuthnRequest> authnRequestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
          AuthnRequest authnRequest = authnRequestBuilder.buildObject();

          // Scoping
          SAMLObjectBuilder<Scoping> scopingBuilder = (SAMLObjectBuilder<Scoping>) builderFactory.getBuilder(Scoping.DEFAULT_ELEMENT_NAME);
          Scoping scoping = scopingBuilder.buildObject();

          // .. IDPList
          SAMLObjectBuilder<IDPList> idpListBuilder = (SAMLObjectBuilder<IDPList>) builderFactory.getBuilder(IDPList.DEFAULT_ELEMENT_NAME);
          IDPList idpList = idpListBuilder.buildObject();
          
          // .. IDPEntry
          SAMLObjectBuilder<IDPEntry> idpEntryBuilder = (SAMLObjectBuilder<IDPEntry>) builderFactory.getBuilder(IDPEntry.DEFAULT_ELEMENT_NAME);
          IDPEntry idpEntry = idpEntryBuilder.buildObject();
          idpEntry.setName("account.htc.com");
          idpEntry.setProviderID("account.htc.com");

          idpList.getIDPEntrys().add(idpEntry);
          scoping.setIDPList(idpList);
            
          // Issuer
          SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
          Issuer issuer = issuerBuilder.buildObject();
          issuer.setValue("https://account.htc.com/service/saml2/");
	 
          authnRequest.setID(UUID.randomUUID().toString());
          authnRequest.setIssuer(issuer);
          authnRequest.setIsPassive(true);
          authnRequest.setProviderName("support.htc.com");
          authnRequest.setScoping(scoping);
          authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

          AuthnRequestMarshaller marshaller = new AuthnRequestMarshaller();

          try {
            Element plaintextElement = marshaller.marshall(authnRequest);
            String originalAuthnRequestString = XMLHelper.nodeToString(plaintextElement);
            System.out.println("AuthnRequest String: " + originalAuthnRequestString);
          } catch (MarshallingException e) {
            System.out.println("Exception: " + e.toString());
          }

          assertTrue(true);
         
     }

     public void testAssertion()
     {
          String assertionId = UUID.randomUUID().toString();
          String accountId = UUID.randomUUID().toString();
          DateTime now = new DateTime();

          XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

          // NameIdentifier
          SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
          NameID nameId = (NameID) nameIdBuilder.buildObject();
          nameId.setValue(accountId);
          nameId.setNameQualifier("account.htc.com");
          nameId.setFormat(NameID.UNSPECIFIED);

          // SubjectConfirmation
          SAMLObjectBuilder confirmationBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
          SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) confirmationBuilder.buildObject();
          confirmationMethod.setNotBefore(now);
          confirmationMethod.setNotOnOrAfter(now.plusMinutes(1));

          SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
          SubjectConfirmation subjectConfirmation = (SubjectConfirmation) subjectConfirmationBuilder.buildObject();
          subjectConfirmation.setSubjectConfirmationData(confirmationMethod);

          // Subject
          SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
          Subject subject = (Subject) subjectBuilder.buildObject();
          subject.setNameID(nameId);
          subject.getSubjectConfirmations().add(subjectConfirmation);

          // Authentication Statement
          SAMLObjectBuilder authStatementBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
          AuthnStatement authnStatement = (AuthnStatement) authStatementBuilder.buildObject();

          // .. Authentication Context
          SAMLObjectBuilder authContextBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME); 
          AuthnContext authnContext = (AuthnContext) authContextBuilder.buildObject();
          // .. .. Authentication Context Class
          SAMLObjectBuilder authContextClassRefBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
          AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) authContextClassRefBuilder.buildObject();
          authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

          authnContext.setAuthnContextClassRef(authnContextClassRef);

          authnStatement.setAuthnInstant(now);
          authnStatement.setSessionIndex(UUID.randomUUID().toString());
          authnStatement.setSessionNotOnOrAfter(now.plus(60));
          authnStatement.setAuthnContext(authnContext);

          // Attributes Statement
          SAMLObjectBuilder attrStatementBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
          AttributeStatement attrStatement = (AttributeStatement) attrStatementBuilder.buildObject();

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
          SAMLObjectBuilder conditionsBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
          Conditions conditions = (Conditions) conditionsBuilder.buildObject();
 
          // .. do-not-cache
          SAMLObjectBuilder doNotCacheConditionBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(OneTimeUse.DEFAULT_ELEMENT_NAME);
          Condition condition = (Condition) doNotCacheConditionBuilder.buildObject();

          conditions.getConditions().add(condition);
          
          // Issuer
          SAMLObjectBuilder issuerBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
          Issuer issuer = (Issuer) issuerBuilder.buildObject();
          issuer.setValue("https://account.htc.com/service/saml2/");

          // Assertion
          SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
          Assertion assertion = (Assertion) assertionBuilder.buildObject();
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

          SAMLObjectBuilder statusCodeBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
          StatusCode statusCode = (StatusCode) statusCodeBuilder.buildObject();
          statusCode.setValue(StatusCode.SUCCESS_URI); 

          SAMLObjectBuilder statusBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
          Status status = (Status) statusBuilder.buildObject();
          status.setStatusCode(statusCode);
          
          SAMLObjectBuilder responseBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
          Response response = (Response) responseBuilder.buildObject();
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

/*
     public void testMarshaller()
     {
        // Get the builder factory
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
         
        // Get the subject builder based on the subject element name
        SubjectBuilder builder = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
         
        // Create the subject
        Subject subject = builder.buildObject();
         
        // Added an NameID and two SubjectConfirmation items - creation of these items is not shown
        subject.setNameID(nameID);
        subject.getSubjectConfirmations().add(subjectConfirmation1);
        subject.getSubjectConfirmations().add(subjectConfirmation2);
         
        // Get the marshaller factory
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
         
        // Get the Subject marshaller
        Marshaller marshaller = marshallerFactory.getMarshaller(subject);
         
        // Marshall the Subject
        Element subjectElement = marshaller.marshall(subject);

        System.out.println("element: " + subjectElement.class.toString() );
        assertTrue(true);
    }
*/

}

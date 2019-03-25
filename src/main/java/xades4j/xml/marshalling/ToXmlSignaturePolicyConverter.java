/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.xml.marshalling;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.xml.bind.xades.*;
import xades4j.xml.bind.xmldsig.XmlDigestMethodType;
import xades4j.xml.bind.xmldsig.XmlTransformType;
import xades4j.xml.bind.xmldsig.XmlTransformsType;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

/**
 * @author Luís
 */
class ToXmlSignaturePolicyConverter implements SignedPropertyDataToXmlConverter
{
    @Override
    public void convertIntoObjectTree(
            PropertyDataObject propData,
            XmlSignedPropertiesType xmlProps,
            Document doc)
    {
        SignaturePolicyData sigPolicyData = (SignaturePolicyData) propData;
        XmlSignaturePolicyIdentifierType xmlSigPolicy = new XmlSignaturePolicyIdentifierType();

        if (null == sigPolicyData.getIdentifier())
        {
            xmlSigPolicy.setSignaturePolicyImplied();
        } else
        {
            xmlSigPolicy.setSignaturePolicyId(getSignaturePolicy(sigPolicyData, doc));
        }
        xmlProps.getSignedSignatureProperties().setSignaturePolicyIdentifier(xmlSigPolicy);
    }

    private XmlSignaturePolicyIdType getSignaturePolicy(SignaturePolicyData sigPolicyData, Document doc)
    {
        XmlSignaturePolicyIdType xmlSigPolicyId = new XmlSignaturePolicyIdType();

        // Identifier
        xmlSigPolicyId.setSigPolicyId(ToXmlUtils.getXmlObjectId(sigPolicyData.getIdentifier()));

        // Hash
        XmlDigestMethodType xmlDigestMethod = new XmlDigestMethodType();
        xmlDigestMethod.setAlgorithm(sigPolicyData.getDigestAlgorithm());
        XmlDigestAlgAndValueType xmlDigest = new XmlDigestAlgAndValueType();
        xmlDigest.setDigestMethod(xmlDigestMethod);
        xmlDigest.setDigestValue(sigPolicyData.getDigestValue());
        xmlSigPolicyId.setSigPolicyHash(xmlDigest);
        XmlTransformsType xmlTransformsType = new XmlTransformsType();

        NodeList childNodes = sigPolicyData.getTransforms().getElement().getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++)
        {
            Node item = childNodes.item(i);
            if (item.getLocalName() != null && item.getLocalName().equals("Transform"))
            {
                XmlTransformType xmlTransformType = new XmlTransformType();
                String algorithm = item.getAttributes().getNamedItem("Algorithm").getTextContent();
                xmlTransformType.setAlgorithm(algorithm);
                NodeList transformChildren = item.getChildNodes();
                for (int j = 0; j < transformChildren.getLength(); j++)
                {
                    Node transformChild = transformChildren.item(j);
                    if (transformChild.getLocalName() != null)
                    {
                        xmlTransformType.getContent().add(transformChild);
                    }
                }
                xmlTransformsType.getTransform().add(xmlTransformType);
            }
        }

        xmlSigPolicyId.setTransforms(xmlTransformsType);

        // Qualifiers
        String url = sigPolicyData.getLocationUrl();
        if (url != null)
        {
            JAXBElement<String> xmlSPURI = new JAXBElement<String>(new QName(QualifyingProperty.XADES_XMLNS, "SPURI"), String.class, url);
            XmlAnyType xmlQualifier = new XmlAnyType();
            xmlQualifier.getContent().add(xmlSPURI);

            XmlSigPolicyQualifiersListType xmlQualifiers = new XmlSigPolicyQualifiersListType();
            xmlQualifiers.getSigPolicyQualifier().add(xmlQualifier);
            xmlSigPolicyId.setSigPolicyQualifiers(xmlQualifiers);
        }

        return xmlSigPolicyId;
    }
}

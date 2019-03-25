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
package xades4j.production;

import com.google.inject.Inject;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.SignaturePolicyIdentifierProperty;
import xades4j.properties.data.PropertyDataObject;
import xades4j.properties.data.SignaturePolicyData;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.utils.MessageDigestUtils;
import xades4j.utils.TransformUtils;
import xades4j.xml.marshalling.algorithms.AlgorithmsParametersMarshallingProvider;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;

/**
 * @author Luís
 */
class DataGenSigPolicy implements PropertyDataObjectGenerator<SignaturePolicyIdentifierProperty>
{
    private final MessageDigestEngineProvider messageDigestProvider;
    private final AlgorithmsProviderEx algorithmsProvider;
    private final AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller;

    @Inject
    public DataGenSigPolicy(
            MessageDigestEngineProvider messageDigestProvider,
            AlgorithmsProviderEx algorithmsProvider,
            AlgorithmsParametersMarshallingProvider algorithmsParametersMarshaller)
    {
        this.messageDigestProvider = messageDigestProvider;
        this.algorithmsProvider = algorithmsProvider;
        this.algorithmsParametersMarshaller = algorithmsParametersMarshaller;
    }

    @Override
    public PropertyDataObject generatePropertyData(
            SignaturePolicyIdentifierProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        try
        {
            // Digest the policy document.
            String digestAlgUri = this.algorithmsProvider.getDigestAlgorithmForReferenceProperties();
            MessageDigest md = this.messageDigestProvider.getEngine(digestAlgUri);
            byte[] policyDoc = prop.getPolicyDocumentData();
            Transforms transforms = null;
            if (prop.getTransforms().size() > 0)
            {
                ByteArrayInputStream bis = new ByteArrayInputStream(policyDoc);
                DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
                documentBuilderFactory.setNamespaceAware(true);
                documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
                documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
                Document document = documentBuilder.parse(bis);

                transforms = TransformUtils.createTransforms(document, this.algorithmsParametersMarshaller, prop.getTransforms());
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                XMLSignatureInput input = transforms.performTransforms(new XMLSignatureInput(policyDoc), bos);
                policyDoc = input.getBytes();
            }
            byte[] policyDigest = MessageDigestUtils.digestStream(md, new ByteArrayInputStream(policyDoc));

            return new SignaturePolicyData(
                    prop.getIdentifier(),
                    digestAlgUri,
                    policyDigest,
                    prop.getLocationUrl(),
                    transforms);

        } catch (IOException ex)
        {
            throw new PropertyDataGenerationException(prop, "Cannot digest signature policy", ex);
        } catch (UnsupportedAlgorithmException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        } catch (ParserConfigurationException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        } catch (SAXException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        } catch (TransformationException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        } catch (CanonicalizationException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        }
    }
}

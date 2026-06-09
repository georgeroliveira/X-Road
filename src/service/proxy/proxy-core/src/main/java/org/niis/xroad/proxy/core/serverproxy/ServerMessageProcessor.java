/*
 * The MIT License
 *
 * Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
 * Copyright (c) 2018 Estonian Information System Authority (RIA),
 * Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
 * Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.niis.xroad.proxy.core.serverproxy;

import ee.ria.xroad.common.CodedException;
import ee.ria.xroad.common.SystemProperties;
import ee.ria.xroad.common.crypto.identifier.DigestAlgorithm;
import ee.ria.xroad.common.identifier.ClientId;
import ee.ria.xroad.common.identifier.SecurityServerId;
import ee.ria.xroad.common.identifier.ServiceId;
import ee.ria.xroad.common.message.RepresentedParty;
import ee.ria.xroad.common.message.RequestHash;
import ee.ria.xroad.common.message.SaxSoapParserImpl;
import ee.ria.xroad.common.message.SoapFault;
import ee.ria.xroad.common.message.SoapHeader;
import ee.ria.xroad.common.message.SoapMessage;
import ee.ria.xroad.common.message.SoapMessageDecoder;
import ee.ria.xroad.common.message.SoapMessageImpl;
import ee.ria.xroad.common.message.SoapUtils;
import ee.ria.xroad.common.util.HttpSender;
import ee.ria.xroad.common.util.RequestWrapper;
import ee.ria.xroad.common.util.ResponseWrapper;
import ee.ria.xroad.common.util.TimeUtils;

import io.opentelemetry.instrumentation.annotations.WithSpan;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.soap.SOAPException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.HttpClient;
import org.niis.xroad.common.core.annotation.ArchUnitSuppressed;
import org.niis.xroad.common.core.exception.XrdRuntimeException;
import org.niis.xroad.globalconf.GlobalConfProvider;
import org.niis.xroad.globalconf.cert.CertChain;
import org.niis.xroad.opmonitor.api.OpMonitoringData;
import org.niis.xroad.proxy.core.conf.SigningCtx;
import org.niis.xroad.proxy.core.messagelog.MessageLog;
import org.niis.xroad.proxy.core.protocol.ProxyMessage;
import org.niis.xroad.proxy.core.protocol.ProxyMessageDecoder;
import org.niis.xroad.proxy.core.protocol.ProxyMessageEncoder;
import org.niis.xroad.proxy.core.util.CommonBeanProxy;
import org.niis.xroad.proxy.core.util.MessageProcessorBase;
import org.niis.xroad.serverconf.ServerConfProvider;
import org.niis.xroad.serverconf.model.Client;
import org.niis.xroad.serverconf.model.DescriptionType;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.AttributesImpl;

import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static ee.ria.xroad.common.ErrorCodes.SERVER_SERVERPROXY_X;
import static ee.ria.xroad.common.ErrorCodes.X_ACCESS_DENIED;
import static ee.ria.xroad.common.ErrorCodes.X_INTERNAL_ERROR;
import static ee.ria.xroad.common.ErrorCodes.X_INVALID_MESSAGE;
import static ee.ria.xroad.common.ErrorCodes.X_INVALID_SECURITY_SERVER;
import static ee.ria.xroad.common.ErrorCodes.X_INVALID_SERVICE_TYPE;
import static ee.ria.xroad.common.ErrorCodes.X_MISSING_SIGNATURE;
import static ee.ria.xroad.common.ErrorCodes.X_MISSING_SOAP;
import static ee.ria.xroad.common.ErrorCodes.X_SERVICE_DISABLED;
import static ee.ria.xroad.common.ErrorCodes.X_SERVICE_FAILED_X;
import static ee.ria.xroad.common.ErrorCodes.X_SERVICE_MALFORMED_URL;
import static ee.ria.xroad.common.ErrorCodes.X_SERVICE_MISSING_URL;
import static ee.ria.xroad.common.ErrorCodes.X_SSL_AUTH_FAILED;
import static ee.ria.xroad.common.ErrorCodes.X_UNKNOWN_MEMBER;
import static ee.ria.xroad.common.ErrorCodes.X_UNKNOWN_SERVICE;
import static ee.ria.xroad.common.ErrorCodes.translateException;
import static ee.ria.xroad.common.ErrorCodes.translateWithPrefix;
import static ee.ria.xroad.common.util.EncoderUtils.encodeBase64;
import static ee.ria.xroad.common.util.MimeUtils.HEADER_HASH_ALGO_ID;
import static ee.ria.xroad.common.util.MimeUtils.HEADER_ORIGINAL_CONTENT_TYPE;
import static ee.ria.xroad.common.util.MimeUtils.HEADER_ORIGINAL_SOAP_ACTION;
import static ee.ria.xroad.common.util.MimeUtils.HEADER_REQUEST_ID;
import static ee.ria.xroad.common.util.TimeUtils.getEpochMillisecond;

@Slf4j
@ArchUnitSuppressed("NoVanillaExceptions")
class ServerMessageProcessor extends MessageProcessorBase {

    private static final String SERVERPROXY_SERVICE_HANDLERS = SystemProperties.PREFIX + "proxy.serverServiceHandlers";

    private final X509Certificate[] clientSslCerts;

    private final List<ServiceHandler> handlers = new ArrayList<>();

    private String originalSoapAction;
    private ProxyMessage requestMessage;
    private ServiceId requestServiceId;
    private SoapMessageImpl responseSoap;
    private SoapFault responseFault;
    private String xRequestId;

    private ProxyMessageDecoder decoder;
    private ProxyMessageEncoder encoder;

    private SigningCtx responseSigningCtx;

    private HttpClient opMonitorHttpClient;
    private OpMonitoringData opMonitoringData;

    ServerMessageProcessor(CommonBeanProxy commonBeanProxy,
                           RequestWrapper request, ResponseWrapper response,
                           HttpClient httpClient, X509Certificate[] clientSslCerts,
                           HttpClient opMonitorHttpClient, OpMonitoringData opMonitoringData) {
        super(commonBeanProxy, request, response, httpClient);

        this.clientSslCerts = clientSslCerts;
        this.opMonitorHttpClient = opMonitorHttpClient;
        this.opMonitoringData = opMonitoringData;

        loadServiceHandlers();
    }

    @Override
    @WithSpan
    public void process() throws Exception {
        log.info("process({})", jRequest.getContentType());

        xRequestId = jRequest.getHeaders().get(HEADER_REQUEST_ID);

        opMonitoringData.setXRequestId(xRequestId);
        updateOpMonitoringClientSecurityServerAddress();
        updateOpMonitoringServiceSecurityServerAddress();

        try {
            readMessage();

            handleRequest();

            sign();
            logResponseMessage();
            writeSignature();

            close();

            postprocess();
        } catch (Exception ex) {
            handleException(ex);
        } finally {
            if (requestMessage != null) {
                requestMessage.consume();
            }
        }
    }

    @Override
    public boolean verifyMessageExchangeSucceeded() {
        return responseSoap != null && responseFault == null;
    }

    private void updateOpMonitoringClientSecurityServerAddress() {
        try {
            X509Certificate authCert = getClientAuthCert();

            if (authCert != null) {
                opMonitoringData.setClientSecurityServerAddress(commonBeanProxy.globalConfProvider.getSecurityServerAddress(
                        commonBeanProxy.globalConfProvider.getServerId(authCert)));
            }
        } catch (Exception e) {
            log.error("Failed to assign operational monitoring data field {}",
                    OpMonitoringData.CLIENT_SECURITY_SERVER_ADDRESS, e);
        }
    }

    private void updateOpMonitoringServiceSecurityServerAddress() {
        try {
            opMonitoringData.setServiceSecurityServerAddress(getSecurityServerAddress());
        } catch (Exception e) {
            log.error("Failed to assign operational monitoring data field {}",
                    OpMonitoringData.SERVICE_SECURITY_SERVER_ADDRESS, e);
        }
    }

    @Override
    protected void preprocess() {
        encoder = new ProxyMessageEncoder(jResponse.getOutputStream(), SoapUtils.getHashAlgoId());

        jResponse.setContentType(encoder.getContentType());
        jResponse.addHeader(HEADER_HASH_ALGO_ID, SoapUtils.getHashAlgoId().name());
    }

    @Override
    protected void postprocess() {
        opMonitoringData.setSucceeded(true);
    }

    private void loadServiceHandlers() {
        String serviceHandlerNames = System.getProperty(SERVERPROXY_SERVICE_HANDLERS);

        if (!StringUtils.isBlank(serviceHandlerNames)) {
            for (String serviceHandlerName : serviceHandlerNames.split(",")) {
                handlers.add(ServiceHandlerLoader.load(serviceHandlerName,
                        commonBeanProxy.serverConfProvider,
                        commonBeanProxy.globalConfProvider));

                log.debug("Loaded service handler: {}", serviceHandlerName);
            }
        }

        handlers.add(new DefaultServiceHandlerImpl(
                commonBeanProxy.serverConfProvider,
                commonBeanProxy.globalConfProvider)); // default handler
    }

    private ServiceHandler getServiceHandler(ProxyMessage request) {
        for (ServiceHandler handler : handlers) {
            if (handler.canHandle(requestServiceId, request)) {
                return handler;
            }
        }

        return null;
    }

    private void handleRequest()
            throws SOAPException, JAXBException, IOException, URISyntaxException,
            ParserConfigurationException, HttpClientCreator.HttpClientCreatorException, SAXException {
        ServiceHandler handler = getServiceHandler(requestMessage);

        if (handler == null) {
            handler = new DefaultServiceHandlerImpl(commonBeanProxy.serverConfProvider, commonBeanProxy.globalConfProvider);
        }

        if (handler.shouldVerifyAccess()) {
            verifyAccess();
        }

        if (handler.shouldVerifySignature()) {
            verifySignature();
        }

        if (handler.shouldLogSignature()) {
            logRequestMessage();
        }

        try {
            handler.startHandling(jRequest, requestMessage, opMonitorHttpClient, opMonitoringData);
            parseResponse(handler);
        } finally {
            handler.finishHandling();
        }
    }

    private void readMessage() throws Exception {
        log.trace("readMessage()");

        originalSoapAction = validateSoapActionHeader(jRequest.getHeaders().get(HEADER_ORIGINAL_SOAP_ACTION));
        requestMessage = new ProxyMessage(jRequest.getHeaders().get(HEADER_ORIGINAL_CONTENT_TYPE)) {
            @Override
            public void soap(SoapMessageImpl soapMessage, Map<String, String> additionalHeaders)
                    throws CertificateEncodingException, IOException {
                super.soap(soapMessage, additionalHeaders);

                updateOpMonitoringDataBySoapMessage(opMonitoringData, soapMessage);

                requestServiceId = soapMessage.getService();

                verifySecurityServer();
                verifyClientStatus();

                responseSigningCtx = commonBeanProxy.signingCtxProvider.createSigningCtx(requestServiceId.getClientId());

                if (SystemProperties.isSslEnabled()) {
                    verifySslClientCert();
                }
            }
        };

        decoder = new ProxyMessageDecoder(commonBeanProxy.globalConfProvider, requestMessage, jRequest.getContentType(), false,
                getHashAlgoId(jRequest));
        try {
            decoder.parse(jRequest.getInputStream());
        } catch (CodedException e) {
            throw e.withPrefix(X_SERVICE_FAILED_X);
        }

        updateOpMonitoringDataByRequest();

        // Check if the input contained all the required bits.
        checkRequest();
    }

    private void updateOpMonitoringDataByRequest() {
        if (requestMessage.getSoap() != null) {
            opMonitoringData.setRequestAttachmentCount(decoder.getAttachmentCount());

            if (decoder.getAttachmentCount() > 0) {
                opMonitoringData.setRequestMimeSize(requestMessage.getSoap().getBytes().length
                        + decoder.getAttachmentsByteCount());
            }
        }
    }

    private void checkRequest() {
        if (requestMessage.getSoap() == null) {
            throw new CodedException(X_MISSING_SOAP, "Request does not have SOAP message");
        }

        if (requestMessage.getSignature() == null) {
            throw new CodedException(X_MISSING_SIGNATURE, "Request does not have signature");
        }
        checkIdentifier(requestMessage.getSoap().getClient());
        checkIdentifier(requestMessage.getSoap().getService());
        checkIdentifier(requestMessage.getSoap().getSecurityServer());
    }

    private void verifyClientStatus() {
        ClientId client = requestServiceId.getClientId();

        String status = commonBeanProxy.serverConfProvider.getMemberStatus(client);

        if (!Client.STATUS_REGISTERED.equals(status)) {
            throw new CodedException(X_UNKNOWN_MEMBER, "Client '%s' not found", client);
        }
    }

    private void verifySslClientCert() throws CertificateEncodingException, IOException {
        log.trace("verifySslClientCert()");

        if (requestMessage.getOcspResponses().isEmpty()) {
            throw new CodedException(X_SSL_AUTH_FAILED,
                    "Cannot verify TLS certificate, corresponding OCSP response is missing");
        }

        String instanceIdentifier = requestMessage.getSoap().getClient().getXRoadInstance();

        X509Certificate trustAnchor = commonBeanProxy.globalConfProvider.getCaCert(instanceIdentifier,
                clientSslCerts[clientSslCerts.length - 1]);

        if (trustAnchor == null) {
            throw XrdRuntimeException.systemInternalError("Unable to find trust anchor");
        }

        try {
            CertChain chain = commonBeanProxy.certChainFactory.create(instanceIdentifier, ArrayUtils.add(clientSslCerts, trustAnchor));
            commonBeanProxy.certHelper.verifyAuthCert(chain, requestMessage.getOcspResponses(), requestMessage.getSoap().getClient());
        } catch (Exception e) {
            throw new CodedException(X_SSL_AUTH_FAILED, e);
        }
    }

    private void verifySecurityServer() {
        final SecurityServerId requestServerId = requestMessage.getSoap().getSecurityServer();

        if (requestServerId != null) {
            final SecurityServerId serverId = commonBeanProxy.serverConfProvider.getIdentifier();

            if (!requestServerId.equals(serverId)) {
                throw new CodedException(X_INVALID_SECURITY_SERVER,
                        "Invalid security server identifier '%s' expected '%s'", requestServerId, serverId);
            }
        }
    }

    private void verifyAccess() {
        log.trace("verifyAccess()");

        if (!commonBeanProxy.serverConfProvider.serviceExists(requestServiceId)) {
            throw new CodedException(X_UNKNOWN_SERVICE, "Unknown service: %s", requestServiceId);
        }

        DescriptionType descriptionType = commonBeanProxy.serverConfProvider.getDescriptionType(requestServiceId);
        if (descriptionType != null && descriptionType != DescriptionType.WSDL) {
            throw new CodedException(X_INVALID_SERVICE_TYPE,
                    "Service is a REST service and cannot be called using SOAP interface");
        }

        if (!commonBeanProxy.serverConfProvider.isQueryAllowed(requestMessage.getSoap().getClient(), requestServiceId)) {
            throw new CodedException(X_ACCESS_DENIED, "Request is not allowed: %s", requestServiceId);
        }

        String disabledNotice = commonBeanProxy.serverConfProvider.getDisabledNotice(requestServiceId);

        if (disabledNotice != null) {
            throw new CodedException(X_SERVICE_DISABLED, "Service %s is disabled: %s", requestServiceId,
                    disabledNotice);
        }
    }

    private void verifySignature() {
        log.trace("verifySignature()");

        decoder.verify(requestMessage.getSoap().getClient(), requestMessage.getSignature());
    }

    private void logRequestMessage() {
        log.trace("logRequestMessage()");

        MessageLog.log(requestMessage.getSoap(), requestMessage.getSignature(), requestMessage.getAttachments(), false, xRequestId);
    }

    private void logResponseMessage() {
        if (responseSoap != null && encoder != null) {
            log.trace("logResponseMessage()");
            // Attachments are not logged here, because response from X-Road 7 server is always batch signed
            MessageLog.log(responseSoap, encoder.getSignature(), List.of(), false, xRequestId);
        }
    }

    private void sendRequest(String serviceAddress, HttpSender httpSender) {
        log.trace("sendRequest({})", serviceAddress);

        URI uri;
        try {
            uri = new URI(serviceAddress);
        } catch (URISyntaxException e) {
            throw new CodedException(X_SERVICE_MALFORMED_URL, "Malformed service address '%s': %s", serviceAddress,
                    e.getMessage());
        }

        log.info("Sending request to {}", uri);
        try {
            opMonitoringData.setRequestOutTs(getEpochMillisecond());
            httpSender.doPost(uri, new ProxyMessageSoapEntity(requestMessage));
            opMonitoringData.setResponseInTs(getEpochMillisecond());
        } catch (Exception ex) {
            if (ex instanceof CodedException) {
                opMonitoringData.setResponseInTs(getEpochMillisecond());
            }
            throw translateException(ex).withPrefix(X_SERVICE_FAILED_X);
        }
    }

    private void parseResponse(ServiceHandler handler) {
        log.trace("parseResponse()");

        preprocess();

        // Preserve the original content type of the service response
        jResponse.addHeader(HEADER_ORIGINAL_CONTENT_TYPE, handler.getResponseContentType());

        try (SoapMessageHandler messageHandler = new SoapMessageHandler()) {
            SoapMessageDecoder soapMessageDecoder = new SoapMessageDecoder(handler.getResponseContentType(),
                    messageHandler, new ResponseSoapParserImpl());
            soapMessageDecoder.parse(handler.getResponseContent());
        } catch (Exception ex) {
            throw translateException(ex).withPrefix(X_SERVICE_FAILED_X);
        }

        // If we received a fault from the service, we just send it back
        // to the client.
        if (responseFault != null) {
            throw responseFault.toCodedException();
        }

        // If we did not parse a response message (empty response
        // from server?), it is an error instead.
        if (responseSoap == null) {
            throw new CodedException(X_INVALID_MESSAGE, "No response message received from service").withPrefix(
                    X_SERVICE_FAILED_X);
        }

        updateOpMonitoringDataByResponse();
    }

    private void updateOpMonitoringDataByResponse() {
        opMonitoringData.setResponseAttachmentCount(encoder.getAttachmentCount());

        if (encoder.getAttachmentCount() > 0) {
            opMonitoringData.setResponseMimeSize(responseSoap.getBytes().length + encoder.getAttachmentsByteCount());
        }
    }

    private void sign() throws Exception {
        log.trace("sign({})", requestServiceId.getClientId());

        encoder.sign(responseSigningCtx);
    }

    private void writeSignature() throws Exception {
        log.trace("writeSignature()");

        encoder.writeSignature();
    }

    private void close() throws Exception {
        log.trace("close()");

        encoder.close();
    }

    private void handleException(Exception ex) throws Exception {
        if (encoder != null) {
            CodedException exception;

            if (ex instanceof CodedException.Fault) {
                exception = (CodedException.Fault) ex;
            } else {
                exception = translateWithPrefix(SERVER_SERVERPROXY_X, ex);
            }

            opMonitoringData.setFaultCodeAndString(exception);
            opMonitoringData.setResponseOutTs(getEpochMillisecond(), false);

            encoder.fault(SoapFault.createFaultXml(exception));
            encoder.close();
        } else {
            throw ex;
        }
    }

    private X509Certificate getClientAuthCert() {
        return clientSslCerts != null ? clientSslCerts[0] : null;
    }

    private static DigestAlgorithm getHashAlgoId(RequestWrapper request) {
        String hashAlgoId = request.getHeaders().get(HEADER_HASH_ALGO_ID);

        if (hashAlgoId == null) {
            throw new CodedException(X_INTERNAL_ERROR, "Could not get hash algorithm identifier from message");
        }

        return DigestAlgorithm.ofName(hashAlgoId);
    }

    private final class DefaultServiceHandlerImpl extends AbstractServiceHandler {

        private HttpSender sender;

        DefaultServiceHandlerImpl(ServerConfProvider serverConfProvider, GlobalConfProvider globalConfProvider) {
            super(serverConfProvider, globalConfProvider);
        }

        @Override
        public boolean shouldVerifyAccess() {
            return true;
        }

        @Override
        public boolean shouldVerifySignature() {
            return true;
        }

        @Override
        public boolean shouldLogSignature() {
            return true;
        }

        @Override
        public boolean canHandle(ServiceId requestSrvcId, ProxyMessage requestProxyMessage) {
            return true;
        }

        @Override
        public void startHandling(RequestWrapper request, ProxyMessage proxyRequestMessage,
                                  HttpClient opMonitorClient, OpMonitoringData monitoringData) {
            sender = createHttpSender();

            log.trace("processRequest({})", requestServiceId);

            String address = serverConfProvider.getServiceAddress(requestServiceId);

            if (address == null || address.isEmpty()) {
                throw new CodedException(X_SERVICE_MISSING_URL, "Service address not specified for '%s'",
                        requestServiceId);
            }

            int timeout = TimeUtils.secondsToMillis(serverConfProvider.getServiceTimeout(requestServiceId));

            sender.setConnectionTimeout(timeout);
            sender.setSocketTimeout(timeout);
            sender.setAttribute(ServiceId.class.getName(), requestServiceId);

            sender.addHeader("accept-encoding", "");
            sender.addHeader("SOAPAction", originalSoapAction);
            sendRequest(address, sender);
        }

        @Override
        public void finishHandling() {
            sender.close();
            sender = null;
        }

        @Override
        public String getResponseContentType() {
            return sender.getResponseContentType();
        }

        @Override
        public InputStream getResponseContent() {
            return sender.getResponseContent();
        }
    }

    private final class SoapMessageHandler implements SoapMessageDecoder.Callback {
        @Override
        public void soap(SoapMessage message, Map<String, String> headers) throws UnsupportedEncodingException {
            responseSoap = (SoapMessageImpl) message;

            opMonitoringData.setResponseSize(responseSoap.getBytes().length);
            opMonitoringData.setResponseOutTs(getEpochMillisecond(), true);

            encoder.soap(responseSoap, headers);
        }

        @Override
        public void attachment(String contentType, InputStream content, Map<String, String> additionalHeaders)
                throws IOException {
            encoder.attachment(contentType, content, additionalHeaders);
        }

        @Override
        public void fault(SoapFault fault) {
            responseFault = fault;
        }

        @Override
        public void onCompleted() {
            // Do nothing.
        }

        @Override
        @ArchUnitSuppressed("NoVanillaExceptions")
        public void onError(Exception t) throws Exception {
            throw t;
        }

        @Override
        public void close() {
            // Do nothing.
        }
    }

    /**
     * Soap parser that adds the request message hash to the response message header.
     *
     * <p>When {@link SystemProperties#getServerProxyAutoInjectMissingHeaders()} is enabled and the service
     * response is a legacy SOAP message without an X-Road header, this parser synthesizes the missing header
     * (reconstructed from the request) before the SOAP body, so the response can be validated and signed like
     * a regular X-Road response. When the toggle is disabled, the strict missing-header rejection is preserved.
     */
    private final class ResponseSoapParserImpl extends SaxSoapParserImpl {

        private static final String SYNTHETIC_PREFIX_XROAD = "xrd";
        private static final String SYNTHETIC_PREFIX_IDENTIFIERS = "id";
        private static final String SYNTHETIC_PREFIX_REPRESENTATION = "repr";

        private boolean inHeader;
        private boolean inBody;
        private boolean inExistingRequestHash;
        private boolean bufferFlushed = true;

        private char[] headerElementTabs;

        private char[] bufferedChars;
        private int bufferedOffset;
        private int bufferedLength;

        // set when a real SOAP header is encountered in the response
        private boolean headerSeen;
        // set when the synthetic header bytes have been written for this response
        private boolean missingHeaderInjected;
        private final Attributes emptyAttributes = new AttributesImpl();

        // force usage of processed XML since we need to write the request hash
        @Override
        protected boolean isProcessedXmlRequired() {
            return true;
        }

        @Override
        protected SoapHeaderHandler getSoapHeaderHandler(SoapHeader header) {
            return new SoapHeaderHandler(header) {
                @Override
                protected void openTag() {
                    super.openTag();
                    inHeader = true;
                    headerSeen = true;
                }

                @Override
                protected void closeTag() {
                    super.closeTag();
                    inHeader = false;
                }
            };
        }

        @Override
        protected void onMissingHeader(SoapHeaderHandler handler) {
            if (!SystemProperties.getServerProxyAutoInjectMissingHeaders()) {
                super.onMissingHeader(handler);
                return;
            }
            // Auto-inject enabled: the synthetic header bytes are written at the SOAP body start
            // (see writeStartElementXml); here we populate the in-memory header from the request so the
            // required-field checks below pass and the response message carries valid metadata
            // (client / service / queryId / protocolVersion) for logging and operational monitoring.
            populateHeader(handler.getHeader());
        }

        @Override
        protected void writeEndElementXml(String prefix, QName element, Attributes attributes, Writer writer) throws IOException {
            if (inHeader && element.equals(QNAME_XROAD_REQUEST_HASH)) {
                inExistingRequestHash = false;
            } else {
                writeBufferedCharacters(writer);
                super.writeEndElementXml(prefix, element, attributes, writer);
            }

            if (inHeader && element.equals(QNAME_XROAD_QUERY_ID)) {
                char[] tabs = headerElementTabs != null ? headerElementTabs : new char[0];
                writeRequestHashElement(prefix, attributes, tabs, writer);
            }
        }

        @Override
        protected void writeStartElementXml(String prefix, QName element, Attributes attributes, Writer writer) throws IOException {
            if (inHeader && element.equals(QNAME_XROAD_REQUEST_HASH)) {
                inExistingRequestHash = true;
            } else {
                if (!inBody && element.equals(QNAME_SOAP_BODY)) {
                    inBody = true;
                    injectMissingHeaderIfNeeded(prefix, writer);
                }

                writeBufferedCharacters(writer);
                super.writeStartElementXml(prefix, element, attributes, writer);
            }
        }

        private void writeBufferedCharacters(Writer writer) throws IOException {
            // Write the characters we ignored at the last characters event
            if (!bufferFlushed) {
                super.writeCharactersXml(bufferedChars, bufferedOffset, bufferedLength, writer);
                bufferFlushed = true;
            }
        }

        @Override
        protected void writeCharactersXml(char[] characters, int start, int length, Writer writer) throws IOException {
            if (inHeader && headerElementTabs == null) {
                String value = new String(characters, start, length);

                if (value.trim().isEmpty()) {
                    headerElementTabs = value.toCharArray();
                }
            }

            // When writing characters outside of the SOAP body, delay this
            // operation until the next event, sometimes we don't want to write
            // these characters, like when we're discarding a header
            if (!inBody && bufferFlushed) {
                bufferCharacters(characters, start, length);
            } else if (!inExistingRequestHash) {
                writeBufferedCharacters(writer);
                super.writeCharactersXml(characters, start, length, writer);
            }
        }

        private void bufferCharacters(char[] characters, int start, int length) {
            if (bufferedChars == null || bufferedChars.length < characters.length) {
                bufferedChars = ArrayUtils.clone(characters);
            } else {
                System.arraycopy(characters, start, bufferedChars, start, length);
            }

            bufferedOffset = start;
            bufferedLength = length;
            bufferFlushed = false;
        }

        /**
         * Writes the {@code xrd:requestHash} element (request message hash) using the request message digest.
         * Shared by the in-stream injection (triggered by the response's own {@code xrd:id}) and by the
         * synthetic header construction, guaranteeing the request hash is written exactly once.
         */
        private void writeRequestHashElement(String prefix, Attributes baseAttributes, char[] tabs, Writer writer) {
            try {
                byte[] hashBytes = requestMessage.getSoap().getHash();
                String hash = encodeBase64(hashBytes);

                AttributesImpl hashAttrs = new AttributesImpl(baseAttributes);
                DigestAlgorithm algoUri = SoapUtils.getHashAlgoId();
                hashAttrs.addAttribute("", "", ATTR_ALGORITHM_ID, "xs:string", algoUri.uri());

                super.writeCharactersXml(tabs, 0, tabs.length, writer);
                super.writeStartElementXml(prefix, QNAME_XROAD_REQUEST_HASH, hashAttrs, writer);
                super.writeCharactersXml(hash.toCharArray(), 0, hash.length(), writer);
                super.writeEndElementXml(prefix, QNAME_XROAD_REQUEST_HASH, hashAttrs, writer);
            } catch (Exception e) {
                throw translateException(e);
            }
        }

        private void injectMissingHeaderIfNeeded(String soapPrefix, Writer writer) throws IOException {
            if (headerSeen || missingHeaderInjected
                    || !SystemProperties.getServerProxyAutoInjectMissingHeaders()) {
                return;
            }

            writeSyntheticHeader(soapPrefix, writer);
            missingHeaderInjected = true;
        }

        /**
         * Writes the synthetic X-Road SOAP header bytes, reconstructed from the request message header,
         * immediately before the SOAP body. The element order follows the X-Road message protocol
         * (PR-MESS v4.0 §2.2): client, service, id, [userId], [issue], [representedParty], protocolVersion,
         * requestHash. The values are copied verbatim from the request header; the request hash is appended
         * the same way the in-stream injection does.
         *
         * <p>Namespace declarations are emitted on the synthetic header element itself because no prefix
         * mappings arrived via SAX events (the envelope was already written to the stream). The SOAP prefix
         * from the body event is reused for the {@code Header} element.
         */
        private void writeSyntheticHeader(String soapPrefix, Writer writer) throws IOException {
            SoapHeader requestHeader = requestMessage.getSoap().getHeader();

            AttributesImpl headerAttributes = new AttributesImpl();
            addNamespaceDeclaration(headerAttributes, SYNTHETIC_PREFIX_XROAD, SoapHeader.NS_XROAD);
            addNamespaceDeclaration(headerAttributes, SYNTHETIC_PREFIX_IDENTIFIERS, QNAME_ID_INSTANCE.getNamespaceURI());
            if (requestHeader.getRepresentedParty() != null) {
                addNamespaceDeclaration(headerAttributes, SYNTHETIC_PREFIX_REPRESENTATION, SoapHeader.NS_REPR);
            }

            super.writeStartElementXml(soapPrefix, QNAME_SOAP_HEADER, headerAttributes, writer);

            writeClientElement(requestHeader.getClient(), writer);
            writeServiceElement(requestHeader.getService(), writer);
            writeXRoadTextElement(QNAME_XROAD_QUERY_ID, requestHeader.getQueryId(), writer);
            if (requestHeader.getUserId() != null) {
                writeXRoadTextElement(QNAME_XROAD_USER_ID, requestHeader.getUserId(), writer);
            }
            if (requestHeader.getIssue() != null) {
                writeXRoadTextElement(QNAME_XROAD_ISSUE, requestHeader.getIssue(), writer);
            }
            if (requestHeader.getRepresentedParty() != null) {
                writeRepresentedPartyElement(requestHeader.getRepresentedParty(), writer);
            }
            writeXRoadTextElement(QNAME_XROAD_PROTOCOL_VERSION, requestHeader.getProtocolVersion().getVersion(), writer);
            writeRequestHashElement(SYNTHETIC_PREFIX_XROAD, emptyAttributes, new char[0], writer);

            super.writeEndElementXml(soapPrefix, QNAME_SOAP_HEADER, emptyAttributes, writer);
        }

        private void writeClientElement(ClientId client, Writer writer) throws IOException {
            super.writeStartElementXml(SYNTHETIC_PREFIX_XROAD, QNAME_XROAD_CLIENT,
                    objectTypeAttribute(client.getObjectType().name()), writer);
            writeIdentifierPart(QNAME_ID_INSTANCE, client.getXRoadInstance(), writer);
            writeIdentifierPart(QNAME_ID_MEMBER_CLASS, client.getMemberClass(), writer);
            writeIdentifierPart(QNAME_ID_MEMBER_CODE, client.getMemberCode(), writer);
            if (client.getSubsystemCode() != null) {
                writeIdentifierPart(QNAME_ID_SUBSYSTEM_CODE, client.getSubsystemCode(), writer);
            }
            super.writeEndElementXml(SYNTHETIC_PREFIX_XROAD, QNAME_XROAD_CLIENT, emptyAttributes, writer);
        }

        private void writeServiceElement(ServiceId service, Writer writer) throws IOException {
            super.writeStartElementXml(SYNTHETIC_PREFIX_XROAD, QNAME_XROAD_SERVICE,
                    objectTypeAttribute(service.getObjectType().name()), writer);
            writeIdentifierPart(QNAME_ID_INSTANCE, service.getXRoadInstance(), writer);
            writeIdentifierPart(QNAME_ID_MEMBER_CLASS, service.getMemberClass(), writer);
            writeIdentifierPart(QNAME_ID_MEMBER_CODE, service.getMemberCode(), writer);
            if (service.getSubsystemCode() != null) {
                writeIdentifierPart(QNAME_ID_SUBSYSTEM_CODE, service.getSubsystemCode(), writer);
            }
            writeIdentifierPart(QNAME_ID_SERVICE_CODE, service.getServiceCode(), writer);
            if (service.getServiceVersion() != null) {
                writeIdentifierPart(QNAME_ID_SERVICE_VERSION, service.getServiceVersion(), writer);
            }
            super.writeEndElementXml(SYNTHETIC_PREFIX_XROAD, QNAME_XROAD_SERVICE, emptyAttributes, writer);
        }

        private void writeRepresentedPartyElement(RepresentedParty representedParty, Writer writer) throws IOException {
            super.writeStartElementXml(SYNTHETIC_PREFIX_REPRESENTATION, QNAME_REPR_REPRESENTED_PARTY,
                    emptyAttributes, writer);
            if (representedParty.getPartyClass() != null) {
                writeTextElement(SYNTHETIC_PREFIX_REPRESENTATION, QNAME_PARTY_CLASS,
                        representedParty.getPartyClass(), writer);
            }
            writeTextElement(SYNTHETIC_PREFIX_REPRESENTATION, QNAME_PARTY_CODE, representedParty.getPartyCode(), writer);
            super.writeEndElementXml(SYNTHETIC_PREFIX_REPRESENTATION, QNAME_REPR_REPRESENTED_PARTY,
                    emptyAttributes, writer);
        }

        private AttributesImpl objectTypeAttribute(String objectType) {
            AttributesImpl attributes = new AttributesImpl();
            attributes.addAttribute(QNAME_ID_INSTANCE.getNamespaceURI(), ATTR_OBJECT_TYPE,
                    SYNTHETIC_PREFIX_IDENTIFIERS + ":" + ATTR_OBJECT_TYPE, "CDATA", objectType);
            return attributes;
        }

        private void addNamespaceDeclaration(AttributesImpl attributes, String prefix, String namespaceUri) {
            attributes.addAttribute("", "", "xmlns:" + prefix, "CDATA", namespaceUri);
        }

        private void writeIdentifierPart(QName element, String value, Writer writer) throws IOException {
            writeTextElement(SYNTHETIC_PREFIX_IDENTIFIERS, element, value, writer);
        }

        private void writeXRoadTextElement(QName element, String value, Writer writer) throws IOException {
            writeTextElement(SYNTHETIC_PREFIX_XROAD, element, value, writer);
        }

        private void writeTextElement(String prefix, QName element, String value, Writer writer) throws IOException {
            super.writeStartElementXml(prefix, element, emptyAttributes, writer);
            super.writeCharactersXml(value.toCharArray(), 0, value.length(), writer);
            super.writeEndElementXml(prefix, element, emptyAttributes, writer);
        }

        /**
         * Populates the response's in-memory header from the request header so that the required-field
         * validation passes and the response message carries valid metadata. Mirrors the fields written to
         * the synthetic header bytes; the request hash is set as well for completeness (it does not affect
         * the signed wire bytes, where the request hash is written exactly once by {@link #writeSyntheticHeader}).
         */
        private void populateHeader(SoapHeader target) {
            SoapHeader requestHeader = requestMessage.getSoap().getHeader();
            target.setClient(requestHeader.getClient());
            target.setService(requestHeader.getService());
            target.setQueryId(requestHeader.getQueryId());
            target.setUserId(requestHeader.getUserId());
            target.setIssue(requestHeader.getIssue());
            target.setRepresentedParty(requestHeader.getRepresentedParty());
            target.setProtocolVersion(requestHeader.getProtocolVersion());
            target.setRequestHash(buildRequestHash());
        }

        private RequestHash buildRequestHash() {
            return new RequestHash(SoapUtils.getHashAlgoId().uri(),
                    encodeBase64(requestMessage.getSoap().getHash()));
        }
    }
}

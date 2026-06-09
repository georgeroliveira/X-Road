/*
 * The MIT License
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
package ee.ria.xroad.common.message;

import ee.ria.xroad.common.ExpectedCodedException;
import ee.ria.xroad.common.identifier.ClientId;
import ee.ria.xroad.common.identifier.ServiceId;
import ee.ria.xroad.common.util.MimeTypes;

import org.junit.Rule;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.InputStream;

import static ee.ria.xroad.common.ErrorCodes.X_MISSING_HEADER;
import static ee.ria.xroad.common.message.SoapMessageTestUtil.QUERY_DIR;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests the {@code onMissingHeader} extension point of {@link SaxSoapParserImpl}: by default a missing
 * header is rejected (strict behaviour), but a subclass may override the hook to handle the missing
 * header differently (e.g. synthesize one). The base stays neutral and free of any policy.
 */
public class SaxSoapParserMissingHeaderHookTest {

    @Rule
    public ExpectedCodedException thrown = ExpectedCodedException.none();

    /**
     * By default the parser rejects a SOAP message without a header.
     */
    @Test
    public void defaultHookRejectsMissingHeader() throws Exception {
        thrown.expectError(X_MISSING_HEADER);

        try (InputStream in = noHeaderMessage()) {
            new SaxSoapParserImpl().parse(MimeTypes.TEXT_XML_UTF8, in);
        }
    }

    /**
     * A subclass that overrides the hook to populate the (otherwise empty) header is able to parse a
     * header-less SOAP message into a valid message instead of failing.
     */
    @Test
    public void overriddenHookHandlesMissingHeader() throws Exception {
        SaxSoapParserImpl parser = new SaxSoapParserImpl() {
            @Override
            protected void onMissingHeader(SoapHeaderHandler handler) {
                SoapHeader header = handler.getHeader();
                header.setClient(ClientId.Conf.create("EE", "BUSINESS", "consumer"));
                // body element of no-header.query is <ns1:test>, so the service code must be "test"
                header.setService(ServiceId.Conf.create("EE", "BUSINESS", "producer", null, "test"));
                header.setQueryId("query-1");
                header.setProtocolVersion(new ProtocolVersion());
            }
        };

        Soap soap;
        try (InputStream in = noHeaderMessage()) {
            soap = parser.parse(MimeTypes.TEXT_XML_UTF8, in);
        }

        assertTrue(soap instanceof SoapMessageImpl);
        SoapMessageImpl message = (SoapMessageImpl) soap;
        assertNotNull(message.getHeader().getService());
        assertEquals("test", message.getService().getServiceCode());
        assertEquals("query-1", message.getQueryId());
    }

    private static InputStream noHeaderMessage() throws Exception {
        return new FileInputStream(QUERY_DIR + "no-header.query");
    }
}

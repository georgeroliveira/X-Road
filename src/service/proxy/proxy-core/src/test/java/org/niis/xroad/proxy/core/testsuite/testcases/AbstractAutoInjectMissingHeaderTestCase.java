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
package org.niis.xroad.proxy.core.testsuite.testcases;

import ee.ria.xroad.common.SystemProperties;
import ee.ria.xroad.common.identifier.ClientId;
import ee.ria.xroad.common.identifier.ServiceId;
import ee.ria.xroad.common.message.SoapHeader;
import ee.ria.xroad.common.message.SoapMessageImpl;

import org.niis.xroad.proxy.core.test.Message;
import org.niis.xroad.proxy.core.test.MessageTestCase;
import org.niis.xroad.proxy.core.test.TestContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base for the "auto-inject missing header" server-proxy test cases.
 *
 * <p>The opt-in toggle is bracketed around the whole exchange via an {@link #execute(TestContext)} override
 * (set before, cleared in a finally) instead of {@code startUp()}/{@code closeDown()}, so the global system
 * property never leaks to other test cases even if the request times out. The suite shuffles the cases and
 * a leaked flag would otherwise flip the strict flag-off regression cases.
 *
 * <p>Abstract on purpose: {@code TestcaseLoader} discovers but cannot instantiate it, so it is skipped.
 */
public abstract class AbstractAutoInjectMissingHeaderTestCase extends MessageTestCase {

    /** Matches a {@code requestHash} start tag regardless of the namespace prefix used. */
    private static final Pattern REQUEST_HASH_START_TAG =
            Pattern.compile("<[A-Za-z0-9._-]+:requestHash[\\s>]");

    @Override
    public boolean execute(TestContext testContext) throws Exception {
        System.setProperty(SystemProperties.SERVER_PROXY_AUTO_INJECT_MISSING_HEADERS, "true");
        try {
            return super.execute(testContext);
        } finally {
            System.clearProperty(SystemProperties.SERVER_PROXY_AUTO_INJECT_MISSING_HEADERS);
        }
    }

    protected SoapMessageImpl assertSignedResponse(Message received) {
        assertThat(received.isFault()).isFalse();
        assertThat(received.getSoap()).isInstanceOf(SoapMessageImpl.class);
        return (SoapMessageImpl) received.getSoap();
    }

    /**
     * Asserts the response carries a synthesized X-Road header reconstructed from the request, with the
     * request hash present exactly once, the expected namespaces declared and the PR-MESS element order.
     */
    protected void assertSynthesizedHeader(Message received, ClientId expectedClient, ServiceId expectedService,
                                           String expectedUserId, String expectedSoapPrefix) throws Exception {
        SoapMessageImpl response = assertSignedResponse(received);
        SoapHeader header = response.getHeader();

        assertThat(header.getClient()).isEqualTo(expectedClient);
        assertThat(header.getService()).isEqualTo(expectedService);
        assertThat(header.getQueryId()).isEqualTo(getQueryId());
        if (expectedUserId != null) {
            assertThat(header.getUserId()).isEqualTo(expectedUserId);
        }
        assertThat(header.getProtocolVersion().getVersion()).isEqualTo("4.0");
        assertThat(header.getRequestHash()).isNotNull();

        String xml = response.getXml();
        assertThat(countRequestHashElements(xml)).isEqualTo(1);
        assertThat(xml).contains("<" + expectedSoapPrefix + ":Header");
        assertThat(xml).contains("xmlns:xrd=\"" + SoapHeader.NS_XROAD + "\"");
        assertThat(xml).contains("xmlns:id=\"http://x-road.eu/xsd/identifiers\"");
        assertSynthesizedHeaderOrder(xml);
    }

    /**
     * Asserts the canonical element order of the synthesized header (which uses the {@code xrd} prefix):
     * client &lt; service &lt; id &lt; protocolVersion &lt; requestHash.
     */
    protected void assertSynthesizedHeaderOrder(String xml) {
        int client = xml.indexOf("<xrd:client");
        int service = xml.indexOf("<xrd:service");
        int id = xml.indexOf("<xrd:id>");
        int protocolVersion = xml.indexOf("<xrd:protocolVersion>");
        int requestHash = xml.indexOf("<xrd:requestHash");

        assertThat(client).isGreaterThanOrEqualTo(0);
        assertThat(client).isLessThan(service);
        assertThat(service).isLessThan(id);
        assertThat(id).isLessThan(protocolVersion);
        assertThat(protocolVersion).isLessThan(requestHash);
    }

    protected int countRequestHashElements(String xml) {
        Matcher matcher = REQUEST_HASH_START_TAG.matcher(xml);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }
}

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

import ee.ria.xroad.common.identifier.ClientId;
import ee.ria.xroad.common.identifier.ServiceId;
import ee.ria.xroad.common.message.SoapMessageImpl;

import org.niis.xroad.proxy.core.test.Message;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * When the request has no optional {@code userId}, the synthesized header must omit {@code xrd:userId}
 * (only the fields present in the request are propagated) and remain valid.
 */
public class MissingHeaderResponseAutoInjectNoUserId extends AbstractAutoInjectMissingHeaderTestCase {

    public MissingHeaderResponseAutoInjectNoUserId() {
        requestFileName = "missing-userId.query";
        responseFile = "no-header-representedparty.answer"; // header-less, body = testQueryResponse
    }

    @Override
    protected void validateNormalResponse(Message receivedResponse) throws Exception {
        assertSynthesizedHeader(receivedResponse,
                ClientId.Conf.create("EE", "BUSINESS", "consumer"),
                ServiceId.Conf.create("EE", "BUSINESS", "producer", null, "testQuery"),
                null, // request carries no userId
                "SOAP-ENV");

        SoapMessageImpl response = assertSignedResponse(receivedResponse);
        assertThat(response.getHeader().getUserId()).isNull();
        assertThat(response.getXml()).doesNotContain("<xrd:userId");
    }
}

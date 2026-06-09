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

import ee.ria.xroad.common.identifier.ServiceId;
import ee.ria.xroad.common.message.RepresentedParty;
import ee.ria.xroad.common.message.SoapHeader;
import ee.ria.xroad.common.message.SoapMessageImpl;

import org.niis.xroad.proxy.core.test.Message;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Auto-inject with a request that carries the optional fields (userId, issue, representedParty): the
 * synthesized header must propagate them, declaring the representation namespace as well.
 */
public class MissingHeaderResponseAutoInjectRepresentedParty extends AbstractAutoInjectMissingHeaderTestCase {

    public MissingHeaderResponseAutoInjectRepresentedParty() {
        requestFileName = "simple-representedparty.query";
        responseFile = "no-header-representedparty.answer";
    }

    @Override
    protected void validateNormalResponse(Message receivedResponse) throws Exception {
        SoapMessageImpl response = assertSignedResponse(receivedResponse);
        SoapHeader header = response.getHeader();

        assertThat(header.getService())
                .isEqualTo(ServiceId.Conf.create("EE", "BUSINESS", "producer", null, "testQuery"));
        assertThat(header.getUserId()).isEqualTo("EE37702211234");
        assertThat(header.getIssue()).isEqualTo("issue-1");
        assertThat(header.getRepresentedParty()).isEqualTo(new RepresentedParty("COM", "MEMBER3"));

        String xml = response.getXml();
        assertThat(countRequestHashElements(xml)).isEqualTo(1);
        assertThat(xml).contains("xmlns:repr=\"" + SoapHeader.NS_REPR + "\"");
        assertThat(xml).contains(":representedParty");
    }
}

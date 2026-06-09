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

import org.niis.xroad.proxy.core.test.Message;

import static ee.ria.xroad.common.ErrorCodes.SERVER_SERVERPROXY_X;
import static ee.ria.xroad.common.ErrorCodes.X_MISSING_BODY;
import static ee.ria.xroad.common.ErrorCodes.X_SERVICE_FAILED_X;

/**
 * With the auto-inject toggle on, a response that has neither header nor body still fails with the
 * accurate {@code X_MISSING_BODY} (the missing header is tolerated and the in-memory header populated,
 * so the next validation step is the body), rather than a missing-header-field error.
 */
public class MissingHeaderResponseAutoInjectNoBody extends AbstractAutoInjectMissingHeaderTestCase {

    public MissingHeaderResponseAutoInjectNoBody() {
        requestFileName = "getstate.query";
        responseFile = "no-header-no-body.answer";
    }

    @Override
    protected void validateFaultResponse(Message receivedResponse) {
        assertErrorCode(SERVER_SERVERPROXY_X, X_SERVICE_FAILED_X, X_MISSING_BODY);
    }
}

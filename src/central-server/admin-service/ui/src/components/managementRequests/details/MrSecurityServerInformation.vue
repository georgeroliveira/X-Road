<!--
   The MIT License

   Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
   Copyright (c) 2018 Estonian Information System Authority (RIA),
   Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
   Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
 -->
<template>
  <data-block
    block-title-key="managementRequestDetails.securityServerInformation"
  >
    <data-line
      label-text-key="managementRequestDetails.ownerName"
      :value="managementRequest.security_server_owner"
    />
    <data-line
      label-text-key="managementRequestDetails.ownerClass"
      :value="managementRequest.security_server_id.member_class"
    />
    <data-line
      label-text-key="managementRequestDetails.ownerCode"
      :value="managementRequest.security_server_id.member_code"
    />
    <data-line
      label-text-key="managementRequestDetails.serverCode"
      :value="managementRequest.security_server_id.server_code"
    />
    <data-line
      label-text-key="managementRequestDetails.address"
      :value="managementRequest.address"
    />
  </data-block>
</template>

<script lang="ts">
import Vue, { defineComponent, PropType } from 'vue';
import { ManagementRequestDetailedView } from '@/openapi-types';
import DataLine from './DetailsLine.vue';
import DataBlock from './DetailsBlock.vue';

export default defineComponent({
  components: { DataBlock, DataLine },
  props: {
    managementRequest: {
      type: Object as PropType<ManagementRequestDetailedView>,
      required: true,
    },
  },
});
</script>

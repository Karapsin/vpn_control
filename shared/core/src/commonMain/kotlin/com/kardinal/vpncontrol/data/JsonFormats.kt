package com.kardinal.vpncontrol.data

import kotlinx.serialization.json.Json

internal val CompactJson = Json {
    explicitNulls = false
}

@OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
internal val PrettyJson = Json {
    explicitNulls = false
    prettyPrint = true
    prettyPrintIndent = "  "
}

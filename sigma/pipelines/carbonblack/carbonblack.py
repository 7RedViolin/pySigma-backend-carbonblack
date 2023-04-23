from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def CarbonBlackResponse_pipeline() -> ProcessingPipeline:
    os_filters = [
        # Windows
        ProcessingItem(
            identifier="cbr_windows_os",
            transformation=AddConditionTransformation({
                "os_type": "windows"
            }),
            rule_conditions=[
                LogsourceCondition(product="windows")
            ]
        ),
        # Linux
        ProcessingItem(
            identifier="cbr_linux_os",
            transformation=AddConditionTransformation({
                "os_type": "linux"
            }),
            rule_conditions=[
                LogsourceCondition(product="linux")
            ]
        ),
        # macOS
        ProcessingItem(
            identifier="cbr_macos_os",
            transformation=AddConditionTransformation({
                "os_type": "osx"
            }),
            rule_conditions=[
                LogsourceCondition(product="macos")
            ]
        )
    ]

    field_mappings = [
        # Process Creation
        ProcessingItem(
            identifier="cbr_process_creation_fieldmapping",
            transformation=FieldMappingTransformation({
                "ProcessId":"process_pid",
                "Image":"process_name",
                "ImagePath":"path",
                "Description":"file_desc",
                "Product":"product_name",
                "Company":"company_name",
                "CommandLine":"cmdline",
                "CurrentDirectory":"process_name",
                "User":"username",
                "md5":"md5",
                "sha256":"sha256",
                "ParentProcessId":"parent_pid",
                "ParentImage":"parent_name"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),
        # File Stuff
        ProcessingItem(
            identifier="cbr_file_change_fieldmapping",
            transformation=FieldMappingTransformation({
                "TargetFilename":"filemod", 
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event")
            ]
        ),
        # Module Load Stuff
        ProcessingItem(
            identifier="cbr_image_load_fieldmapping",
            transformation=FieldMappingTransformation({
                "ImageLoaded":"modload",
            }),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Registry Stuff
        ProcessingItem(
            identifier="cbr_registry_fieldmapping",
            transformation=FieldMappingTransformation({
                "TargetObject": "regmod"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set")
            ]
        ),
        # Network Stuff
        ProcessingItem(
            identifier="cbr_network_fieldmapping",
            transformation=FieldMappingTransformation({
                "DestinationHostname":"domain:",
                "DestinationPort":"ipport",
                "DestinationIp":"ipaddr",
                "SourceIp":"ipaddr",
                "SourcePort":"ipport",
                "dst_ip":"ipaddr",
                "src_ip":"ipaddr",
                "dst_port":"ipport",
                "src_port":"ipport"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        )
    ]

    change_logsource_info = [
        # Add service to be CarbonBlackResponse for pretty much everything
        ProcessingItem(
            identifier="cbr_logsource",
            transformation=ChangeLogsourceTransformation(
                service="carbonblackresponse"
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="image_load"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),
    ]

    unsupported_rule_types = [
        # Show error if unsupported option
        ProcessingItem(
            identifier="cbr_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation("Rule type not yet supported by the SentinelOne Sigma backend"),
            rule_condition_negation=True,
            rule_conditions=[
                RuleProcessingItemAppliedCondition("cbr_logsource")
            ]
        )
    ]

    return ProcessingPipeline(
        name="carbonblack response pipeline",
        allowed_backends=frozenset(),                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=50,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            *os_filters,
            *field_mappings,
            *change_logsource_info,
            *unsupported_rule_types
        ]
    )

def CarbonBlack_pipeline() -> ProcessingPipeline:

    os_filters = [
        # Windows
        ProcessingItem(
            identifier="cb_windows_os",
            transformation=AddConditionTransformation({
                "device_os": "WINDOWS"
            }),
            rule_conditions=[
                LogsourceCondition(product="windows")
            ]
        ),
        # Linux
        ProcessingItem(
            identifier="cb_linux_os",
            transformation=AddConditionTransformation({
                "device_os": "LINUX"
            }),
            rule_conditions=[
                LogsourceCondition(product="linux")
            ]
        ),
        # macOS
        ProcessingItem(
            identifier="cb_macos_os",
            transformation=AddConditionTransformation({
                "device_os": "MAC"
            }),
            rule_conditions=[
                LogsourceCondition(product="macos")
            ]
        )
    ]

    field_mappings = [
        # Process Creation
        ProcessingItem(
            identifier="s1_process_creation_fieldmapping",
            transformation=FieldMappingTransformation({
                "ProcessId":"process_pid",
                "Image":"process_name",
                "Description":"process_file_description",
                "Product":"process_product_name",
                "Company":"process_company_name",
                "CommandLine":"process_cmdline",
                "CurrentDirectory":"process_name",
                "User":"process_username",
                "IntegrityLevel":"process_integrity_level",
                "md5":"process_hash",
                "sha256":"process_hash",
                "ParentProcessId":"parent_pid",
                "ParentImage":"parent_name",
                "ParentCommandLine":"parent_cmdline",
                "OriginalFileName":"process_original_filename"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),
        # File Stuff
        ProcessingItem(
            identifier="s1_file_change_fieldmapping",
            transformation=FieldMappingTransformation({
                "TargetFilename":"filemod_name", 
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event")
            ]
        ),
        # Module Load Stuff
        ProcessingItem(
            identifier="s1_image_load_fieldmapping",
            transformation=FieldMappingTransformation({
                "ImageLoaded":"modload_name",
                "Image": "process_name",
                "CommandLine":"process_cmdline",
                "ParentImage":"parent_name",
                "ParentCommandLine":"parent_cmdline",
                "sha256":"modload_hash",
                "md5": "modload_hash",
                "Signature":"modload_publisher"
            }),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        # Registry Stuff
        ProcessingItem(
            identifier="s1_registry_fieldmapping",
            transformation=FieldMappingTransformation({
                "TargetObject": "regmod_name"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set")
            ]
        ),
        # Network Stuff
        ProcessingItem(
            identifier="s1_network_fieldmapping",
            transformation=FieldMappingTransformation({
                "DestinationHostname":"netconn_domain",
                "DestinationPort":"netconn_port",
                "DestinationIp":["netconn_ipv4","netconn_ipv6"],
                "User":"process_username",
                "SourceIp":["netconn_ipv4","netconn_ipv6"],
                "SourcePort":"netconn_port",
                "Protocol":["netconn_protocol", "netconn_application_protocol"],
                "dst_ip":["netconn_ipv4","netconn_ipv6"],
                "src_ip":["netconn_ipv4","netconn_ipv6"],
                "dst_port":"netconn_port",
                "src_port":"netconn_port"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        )
    ]

    change_logsource_info = [
        # Add service to be SentinelOne for pretty much everything
        ProcessingItem(
            identifier="cb_logsource",
            transformation=ChangeLogsourceTransformation(
                service="carbonblack"
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="image_load"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        ),
    ]

    unsupported_rule_types = [
        # Show error if unsupported option
        ProcessingItem(
            identifier="cb_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation("Rule type not yet supported by the SentinelOne Sigma backend"),
            rule_condition_negation=True,
            rule_conditions=[
                RuleProcessingItemAppliedCondition("cb_logsource")
            ]
        )
    ]

    return ProcessingPipeline(
        name="carbonblack pipeline",
        allowed_backends=frozenset(),                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=50,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            *os_filters,
            *field_mappings,
            *change_logsource_info,
            *unsupported_rule_types
        ]
    )
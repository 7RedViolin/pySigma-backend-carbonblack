import pytest
from sigma.collection import SigmaCollection
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.pipelines.carbonblack import CarbonBlackResponse_pipeline, CarbonBlack_pipeline

@pytest.fixture
def cbr_backend():
    return CarbonBlackBackend(CarbonBlackResponse_pipeline())

@pytest.fixture
def cb_backend():
    return CarbonBlackBackend(CarbonBlack_pipeline())

def test_cbr_windows_os_filter(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['os_type:windows AND process_name:valueA']

def test_cbr_linux_os_filter(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['os_type:linux AND process_name:valueA']

def test_cbr_osx_os_filter(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['os_type:osx AND process_name:valueA']

def test_cbr_field_mapping(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    ImagePath: bar bar
                    Description: foo bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: etc
                    User: administrator
                    md5: asdfasdfasdfasdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    TargetFilename: test.txt
                    ImageLoaded: test.dll
                    TargetObject: HKCU
                    DestinationHostname: google.com
                    DestinationPort: 445
                    DestinationIp: 1.1.1.1
                    SourceIp: 2.2.2.2
                    SourcePort: 135
                    dst_ip: 3.3.3.3
                    src_ip: 4.4.4.4
                    dst_port: 80
                    src_port: 443
                condition: sel
        """)
    ) == ['process_pid:12 AND process_name:valueA AND path:bar\\ bar AND file_desc:foo\\ bar AND product_name:bar\\ foo AND ' + 
          'company_name:foo\\ foo AND cmdline:invoke-mimiktaz AND process_name:etc AND username:administrator AND ' + 
          'md5:asdfasdfasdfasdfasdf AND sha256:asdfasdfasdfasdfasdfasdfasdfasdf AND parent_pid:13 AND parent_name:valueB AND ' + 
          'filemod:test.txt AND modload:test.dll AND regmod:HKCU AND domain:google.com AND ipport:445 AND ipaddr:1.1.1.1 AND ' + 
          'ipaddr:2.2.2.2 AND ipport:135 AND ipaddr:3.3.3.3 AND ipaddr:4.4.4.4 AND ipport:80 AND ipport:443']

def test_cbr_unsupported_rule_type(cbr_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_cbr_unsupported_field_name(cbr_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )

def test_cb_windows_os_filter(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['device_os:WINDOWS AND process_name:valueA']

def test_cb_linux_os_filter(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['device_os:LINUX AND process_name:valueA']

def test_cb_osx_os_filter(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['device_os:MAC AND process_name:valueA']

def test_cb_field_mapping(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    Description: foo bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: etc
                    User: administrator
                    IntegrityLevel: bar bar
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentCommandLine: invoke-atomic
                    OriginalFileName: cobalt.exe
                    TargetFilename: test.txt
                    ImageLoaded: test.dll
                    Sginature: Microsoft
                    TargetObject: HKCU
                    DestinationHostname: google.com
                    DestinationPort: 445
                    DestinationIp: 1.1.1.1
                    SourceIp: 2.2.2.2
                    SourcePort: 135
                    Protocol: UDP
                    dst_ip: 3.3.3.3
                    src_ip: 4.4.4.4
                    dst_port: 80
                    src_port: 443
                    DstPort: 8080
                    SrcPort: 5900
                condition: sel
        """)
    ) == ['process_pid:12 AND process_name:valueA AND process_file_description:foo\\ bar AND process_product_name:bar\\ foo AND ' + 
          'process_company_name:foo\\ foo AND process_cmdline:invoke-mimikatz AND process_name:etc AND ' + 
          'process_username:administrator AND process_integrity_level:bar\\ bar AND parent_pid:13 AND parent_name:valueB AND ' + 
          'parent_cmdline:invoke-atomic AND process_original_filename:cobalt.exe AND filemod_name:test.txt AND ' + 
          'modload_name:test.dll AND modload_publisher:Microsoft AND regmod_name:HKCU AND netconn_domain:google.com AND ' + 
          'netconn_port:445 AND (netconn_ipv4:1.1.1.1 OR netconn_ipv6:1.1.1.1) AND (netconn_ipv4:2.2.2.2 OR netconn_ipv6:2.2.2.2) AND ' + 
          'netconn_port:135 AND (netconn_protocol:UDP OR netconn_application_protocol:UDP) AND (netconn_ipv4:3.3.3.3 OR netconn_ipv6:3.3.3.3) AND ' + 
          '(netconn_ipv4:4.4.4.4 OR netconn_ipv6:4.4.4.4) AND netconn_port:80 AND netconn_port:443 AND netconn_port:8080 AND netconn_port:5900']

def test_cb_process_field_mapping(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    md5: asdfasdfasdfasdf
                    sha256: qwerqwerqwerqwer
                condition: sel
        """)
    ) == ['process_hash:asdfasdfasdfasdf AND process_hash:qwerqwerqwerqwer']

def test_cb_image_load_field_mapping(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: image_load
                product: test_product
            detection:
                sel:
                    md5: asdfasdfasdfasdf
                    sha256: qwerqwerqwerqwer
                condition: sel
        """)
    ) == ['modload_hash:asdfasdfasdfasdf AND modload_hash:qwerqwerqwerqwer']

def test_cb_unsupported_rule_type(cb_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_cb_unsupported_field_name(cb_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )

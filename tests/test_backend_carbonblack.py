import pytest
from sigma.collection import SigmaCollection
from sigma.backends.carbonblack import CarbonBlackBackend

@pytest.fixture
def carbonblack_backend():
    return CarbonBlackBackend()

def test_carbonblack_and_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['fieldA:valueA fieldB:valueB']

def test_carbonblack_or_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['fieldA:valueA OR fieldB:valueB']

def test_carbonblack_and_or_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['(fieldA:valueA1 OR fieldA:valueA2) (fieldB:valueB1 OR fieldB:valueB2)']

def test_carbonblack_or_and_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['(fieldA:valueA1 fieldB:valueB1) OR (fieldA:valueA2 fieldB:valueB2)']

def test_carbonblack_not_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                condition: not sel
        """)
    ) == ['-fieldA:valueA']

def test_carbonblack_contains_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    fieldA|contains: valueA
                condition: sel
        """)
    ) == ['fieldA:valueA*']

def test_carbonblack_startswith_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    fieldA|startswith: valueA
                condition: sel
        """)
    ) == ['fieldA:valueA*']

def test_carbonblack_endswith_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    fieldA|endswith: valueA
                condition: sel
        """)
    ) == ['fieldA:valueA']

def test_carbonblack_in_expression(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['fieldA:valueA OR fieldA:valueB OR fieldA:valueC*']

def test_carbonblack_regex_query(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['fieldA:foo.*bar fieldB:foo']

def test_carbonblack_cidr_query(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['field:192.168.*']

def test_carbonblack_range_query(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|gte: 5
                    fieldB|gt: 6
                    fieldC|lte: 7
                    fieldD|lt: 8
                condition: sel

        """)
    ) == ['fieldA:[5 TO *] fieldB:[6 TO *] fieldC:[* TO 7] fieldD:[* TO 8]']

def test_carbonblack_convert_string_value(carbonblack_backend : CarbonBlackBackend):
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: this contains a space
                    fieldB: this(contains)parenthesis
                    fieldC: "thiscontainsacolon:"
                condition: sel
        """)
    ) == ['fieldA:this\\ contains\\ a\\ space fieldB:this\(contains\)parenthesis fieldC:thiscontainsacolon\:']

def test_carbonblack_default_output(carbonblack_backend : CarbonBlackBackend):
    """Test for output format format1."""
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field: valueA
                condition: sel
        """)
    ) == ['field:valueA']

def test_carbonblack_json_output(carbonblack_backend : CarbonBlackBackend):
    """Test for output format json."""
    assert carbonblack_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    field: valueA
                condition: sel
        """), "json"
    ) == {"queries":[{"query":'field:valueA', "title":"Test", "id":None, "description":None}]}
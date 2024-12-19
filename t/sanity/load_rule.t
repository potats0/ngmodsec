use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: module initialization
--- config
    error_log logs/error.log notice;
    location /test {
        rule 'rule 1000 http.uri contains "a";';
        rule 'rule 1002 http.uri contains "b";';
        return 200 "ok";
    }
--- request
GET /test
--- error_log
rule directive has 2 arguments
processing rule: 'rule 1000 http.uri contains "a";'
arg[0]: 'rule'
arg[1]: 'rule 1000 http.uri contains "a";'
rule manager initialized
parsing rule: rule 1000 http.uri contains "a";
rule parsed successfully
rule directive has 2 arguments
processing rule: 'rule 1002 http.uri contains "b";'
arg[0]: 'rule'
arg[1]: 'rule 1002 http.uri contains "b";'
rule manager has been obtained
parsing rule: rule 1002 http.uri contains "b";
rule parsed successfully
rule_mg status: max_rules=10000, rules_count=2
rule IDs:
  [0] rule_id=1000
    sub_rules_count=1
    Rule AndBits:
      Threat ID: 256001
      Pattern ID: 0
    Sub-rule :
      AND mask: 0x0001
      NOT mask: 0x0000
  [1] rule_id=1002
    sub_rules_count=1
    Rule AndBits:
      Threat ID: 256513
      Pattern ID: 0
    Sub-rule :
      AND mask: 0x0001
      NOT mask: 0x0000
String Match Contexts:
Match Context 1:
  Pattern Count: 2
  Pattern 0:
    Content: a
    HS Flags: 0x0000
    Relations Count: 1
      Threat ID: 256001
      Pattern ID: 0
      And bit: 1
  Pattern 1:
    Content: b
    HS Flags: 0x0000
    Relations Count: 1
      Threat ID: 256513
      Pattern ID: 0
      And bit: 1
Match Context 2: <empty>
Match Context 3: <empty>
--- no_error_log
[error]

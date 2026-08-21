package io.just.sast.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** YAML 规则 → RuleSet。 */
public final class YamlRuleLoader {

    @SuppressWarnings("unchecked")
    public RuleSet load(InputStream in) throws IOException {
        if (in == null) {
            throw new IOException("规则流为空");
        }
        Object root = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
        if (!(root instanceof Map<?, ?> map)) {
            throw new IOException("规则格式错误：顶层必须是 map");
        }
        Object rulesObj = map.get("rules");
        if (!(rulesObj instanceof List<?> list)) {
            throw new IOException("规则格式错误：缺少 rules 列表");
        }
        List<Rule.SinkRule> sinks = new ArrayList<>();
        List<Rule.MagicEntryRule> entries = new ArrayList<>();
        List<Rule.SourceRule> sources = new ArrayList<>();
        List<Rule.ModelRule> models = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> ruleMap)) {
                continue;
            }
            String kind = str(ruleMap, "kind");
            String id = str(ruleMap, "id");
            if (id == null || kind == null) {
                continue;
            }
            if (kind.equals("sink")) {
                sinks.add(parseSink(id, ruleMap));
            } else if (kind.equals("magic-entry")) {
                entries.add(parseEntry(id, ruleMap));
            } else if (kind.equals("source")) {
                sources.add(parseSource(id, ruleMap));
            } else if (kind.equals("model")) {
                models.add(parseModel(id, ruleMap));
            }
        }
        return new RuleSet(List.copyOf(sinks), List.copyOf(entries), List.copyOf(sources), List.copyOf(models));
    }

    @SuppressWarnings("unchecked")
    private Rule.SinkRule parseSink(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        Map<?, ?> call = (Map<?, ?>) match.get("call");
        if (call == null) {
            throw new IOException("sink 规则 " + id + " 缺少 match.call");
        }
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        List<Rule.TaintedPos> tainted = new ArrayList<>();
        Object taintedObj = ruleMap.get("tainted");
        if (taintedObj instanceof List<?> taintedList) {
            for (Object t : taintedList) {
                if (t instanceof Map<?, ?> pos) {
                    if (pos.get("receiver") instanceof Boolean b && b) {
                        tainted.add(Rule.TaintedPos.Receiver.INSTANCE);
                    } else if (pos.get("arg") instanceof Number n) {
                        tainted.add(new Rule.TaintedPos.Arg(n.intValue()));
                    }
                }
            }
        }
        return new Rule.SinkRule(id, str(ruleMap, "category"), str(ruleMap, "severity"),
                callMatcher, List.copyOf(tainted));
    }

    @SuppressWarnings("unchecked")
    private Rule.MagicEntryRule parseEntry(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        Map<?, ?> method = (Map<?, ?>) match.get("method");
        if (method == null) {
            throw new IOException("magic-entry 规则 " + id + " 缺少 match.method");
        }
        Rule.MethodMatcher methodMatcher = new Rule.MethodMatcher(
                matchOf(method.get("name")),
                matchNullable(method.get("descriptor")));
        String implementsType = null;
        Object cls = match.get("class");
        if (cls instanceof Map<?, ?> classMap && classMap.get("implements") != null) {
            implementsType = classMap.get("implements").toString();
        }
        return new Rule.MagicEntryRule(id, str(ruleMap, "entryKind"), methodMatcher, implementsType);
    }

    @SuppressWarnings("unchecked")
    private Rule.SourceRule parseSource(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        Map<?, ?> call = (Map<?, ?>) match.get("call");
        if (call == null) {
            throw new IOException("source 规则 " + id + " 缺少 match.call");
        }
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        return new Rule.SourceRule(id, str(ruleMap, "bridge"), callMatcher);
    }

    @SuppressWarnings("unchecked")
    private Rule.ModelRule parseModel(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        Map<?, ?> call = (Map<?, ?>) match.get("call");
        if (call == null) {
            throw new IOException("model 规则 " + id + " 缺少 match.call");
        }
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        Map<String, List<String>> actions = new HashMap<>();
        Object actionsObj = ruleMap.get("actions");
        if (actionsObj instanceof Map<?, ?> actionsMap) {
            for (Map.Entry<?, ?> e : actionsMap.entrySet()) {
                String target = e.getKey().toString();
                List<String> sources = new ArrayList<>();
                if (e.getValue() instanceof List<?> srcList) {
                    for (Object s : srcList) {
                        sources.add(s.toString());
                    }
                }
                actions.put(target, List.copyOf(sources));
            }
        }
        return new Rule.ModelRule(id, callMatcher, Map.copyOf(actions));
    }

    private static Match matchOf(Object raw) throws IOException {
        if (raw == null) {
            throw new IOException("匹配值缺失");
        }
        return Match.of(raw.toString());
    }

    private static Match matchNullable(Object raw) {
        return raw == null ? null : Match.of(raw.toString());
    }

    private static String str(Map<?, ?> map, String key) {
        Object v = map.get(key);
        return v != null ? v.toString() : null;
    }
}

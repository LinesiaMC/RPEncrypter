package org.powernukkitx.rpencrypter.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Shrinks a JSON UI file with the game's own means: templates and variables.
 *
 * Generated menus repeat the same control hundreds of times with a few values changed (a texture,
 * an offset, the range in a binding). Encrypted, these repeats can't be compressed. Here, controls
 * of the same shape become instances of one template added at the root of the namespace: the
 * instance keeps only what differs, as overriding properties for its own direct properties, as
 * {@code $variables} for deeper ones. Passes repeat, so that parents of factored controls get
 * factored in turn.
 *
 * Variables are only placed on properties that the game's own interface already sets through a
 * variable ({@link #VARIABLE_PROPERTIES}), never on a value that is itself a variable reference.
 * Root controls are never touched (other files can inherit from them). Before anything is kept,
 * the result is expanded back and compared with the original: a file that doesn't come back
 * identical, that doesn't parse, or that the parser would rewrite in any way (duplicate keys,
 * escapes) is left exactly as it was.
 */
public final class JsonUiCompressor {

    /** Properties set through a variable somewhere in the game's own interface files. */
    static final Set<String> VARIABLE_PROPERTIES = Set.of(
            "allow_scroll_even_when_content_fits", "alpha", "always_handle_scrolling", "analog_button_name",
            "anchor_from", "anchor_to", "animation_reset_name", "anims", "background_color",
            "binding_collection_name", "binding_collection_prefix", "binding_condition", "binding_name",
            "binding_name_override", "binding_type", "bindings", "button_mappings",
            "button_up_right_of_first_refusal", "clip_direction", "clip_state_change_event", "clips_children",
            "close_on_player_hurt", "collection_name", "color", "consume_hover_events", "control_id",
            "control_ids", "control_name", "controls", "default_focus_precedence", "destroy_at_end",
            "dropdown_area", "dropdown_name", "duration", "enable_directional_toggling", "enable_profanity_filter",
            "enabled", "end_event", "factory", "factory_variables", "fill", "focus_change_down",
            "focus_change_left", "focus_change_right", "focus_change_up", "focus_container",
            "focus_container_custom_left", "focus_container_custom_up", "focus_enabled", "focus_identifier",
            "focus_magnet_enabled", "focus_navigation_mode_down", "focus_navigation_mode_left",
            "focus_navigation_mode_right", "focus_navigation_mode_up", "focus_wrap_enabled", "font_scale_factor",
            "font_size", "font_type", "force_render_below", "frame_count", "from", "from_button_id",
            "gamepad_cursor", "grayscale", "grid_dimension_binding", "grid_dimensions", "grid_item_template",
            "hide_hyphen", "hover_button_name", "hover_text_max_width", "ignored", "images", "inner_radius",
            "iterate_left_button_name", "iterate_right_button_name", "jump_to_bottom_on_update", "layer",
            "line_padding", "localize", "locked_alpha", "locked_color", "max_length", "max_size",
            "maximum_grid_items", "min_size", "name", "next_sub_page_button_name", "offset", "orientation",
            "outer_radius", "place_holder_text_hover_color", "prev_sub_page_button_name", "primary_color",
            "priority", "property_bag", "radio_toggle_group", "requires", "reset_on_focus_lost",
            "resolve_sibling_scope", "rotation", "scrollbar_always_visible", "secondary_color",
            "select_button_name", "shadow", "size", "skin_pack_collection_name", "slice_count",
            "slider_collection_name", "slider_deselected_button", "slider_direction", "slider_name",
            "slider_select_on_hover", "slider_selected_button", "slider_small_decrease_button",
            "slider_small_increase_button", "slider_steps", "slider_track_button", "source_control_name",
            "source_property_name", "text", "text_alignment", "text_box_name", "text_color", "text_control",
            "text_edit_box_grid_collection_name", "text_labels", "text_tts", "text_type", "texture",
            "texture_file_system", "tiled", "to", "to_button_id", "toggle_default_state",
            "toggle_grid_collection_name", "toggle_group_default_selected", "toggle_group_forced_index",
            "toggle_name", "toggle_off_button", "toggle_on_button", "tooltip_area", "tooltip_name",
            "tooltip_tts_value", "touch_mode", "tts_control_header", "tts_control_type_order_priority",
            "tts_ignore_count", "tts_index_priority", "tts_inherit_siblings", "tts_name",
            "tts_override_control_value", "tts_section_header", "tts_skip_enumeration", "tts_toggle_off",
            "tts_toggle_on", "tts_value_changed", "use_custom_pocket_toast", "uv", "uv_size", "variables",
            "virtual_keyboard_buffer_control", "visible"
    );

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private static final String DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final int MAX_PASSES = 8;
    private static final int MIN_GAIN = 64;

    private final String templatePrefix;
    private final Set<String> usedNames = new HashSet<>();
    private int templateCounter;
    private int variableCounter;

    private JsonUiCompressor(String path) {
        int salt = Math.floorMod(path.hashCode(), 36 * 36 * 36);
        this.templatePrefix = "zq" + base36(salt, 3);
    }

    /** The compressed file, or the input itself when it isn't a UI namespace or doesn't shrink safely. */
    public static byte[] compress(String path, byte[] minified) {
        try {
            String text = new String(minified, StandardCharsets.UTF_8);
            JsonElement parsed = parse(text);
            if (!parsed.isJsonObject() || !parsed.getAsJsonObject().has("namespace")
                    || !parsed.getAsJsonObject().get("namespace").isJsonPrimitive()) {
                return minified;
            }
            if (!GSON.toJson(parsed).equals(text)) {
                return minified; // the parser would change something: not ours to touch
            }
            JsonObject root = parsed.getAsJsonObject();
            String namespace = root.get("namespace").getAsString();
            JsonObject original = root.deepCopy();
            JsonUiCompressor compressor = new JsonUiCompressor(path);
            for (String key : root.keySet()) compressor.usedNames.add(nameOf(key));
            int templates = 0;
            for (int pass = 0; pass < MAX_PASSES; pass++) {
                int made = compressor.pass(root, namespace);
                if (made == 0) break;
                templates += made;
            }
            if (templates == 0) return minified;
            if (!compressor.expand(root, namespace).equals(original)) return minified;
            byte[] out = GSON.toJson(root).getBytes(StandardCharsets.UTF_8);
            return out.length < minified.length ? out : minified;
        } catch (RuntimeException | StackOverflowError e) {
            return minified;
        }
    }

    // ─── one pass ────────────────────────────────────────────────────────────

    private record Def(String key, JsonObject value, JsonObject parent, List<JsonObject> ancestors) {}

    private record Leaf(List<Object> path, int depth, JsonElement value) {}

    private record Candidate(int gain, List<Def> members, List<Integer> varying, List<Leaf> shape) {}

    private int pass(JsonObject root, String namespace) {
        List<Def> defs = new ArrayList<>();
        collect(root, new ArrayList<>(), 0, null, defs);

        Map<String, List<Def>> groups = new LinkedHashMap<>();
        for (Def def : defs) {
            String base = baseOf(def.key());
            groups.computeIfAbsent(base + "\u0000" + skeleton(def.value(), 0, null), k -> new ArrayList<>()).add(def);
        }

        List<Candidate> candidates = new ArrayList<>();
        for (List<Def> members : groups.values()) {
            if (members.size() < 2) continue;
            List<List<Leaf>> leaves = new ArrayList<>();
            for (Def member : members) {
                List<Leaf> list = new ArrayList<>();
                leaves(member.value(), 1, new ArrayList<>(), list);
                leaves.add(list);
            }
            List<Leaf> shape = leaves.get(0);
            List<Integer> varying = new ArrayList<>();
            for (int i = 0; i < shape.size(); i++) {
                String first = GSON.toJson(shape.get(i).value());
                for (List<Leaf> other : leaves) {
                    if (!GSON.toJson(other.get(i).value()).equals(first)) {
                        varying.add(i);
                        break;
                    }
                }
            }
            long full = 0, instances = 0;
            for (int m = 0; m < members.size(); m++) {
                Def member = members.get(m);
                full += utf8(GSON.toJson(member.key())) + 1 + utf8(GSON.toJson(member.value()));
                instances += member.key().length() + 16;
                for (int i : varying) {
                    Leaf leaf = leaves.get(m).get(i);
                    instances += utf8(GSON.toJson(leaf.value()))
                            + (leaf.depth() == 2 ? utf8(GSON.toJson((String) leaf.path().get(0))) + 1 : 6);
                }
            }
            long gain = full - instances - utf8(GSON.toJson(members.get(0).value())) - 12;
            if (gain > MIN_GAIN) candidates.add(new Candidate((int) Math.min(gain, Integer.MAX_VALUE), members, varying, shape));
        }

        candidates.sort((a, b) -> Integer.compare(b.gain(), a.gain()));
        Set<JsonObject> taken = Collections.newSetFromMap(new IdentityHashMap<>());
        Set<JsonObject> blocked = Collections.newSetFromMap(new IdentityHashMap<>());
        int made = 0;
        for (Candidate candidate : candidates) {
            boolean free = true;
            for (Def member : candidate.members()) {
                if (taken.contains(member.value()) || blocked.contains(member.value())) { free = false; break; }
                for (JsonObject ancestor : member.ancestors()) {
                    if (taken.contains(ancestor)) { free = false; break; }
                }
                if (!free) break;
            }
            if (!free) continue;
            for (Def member : candidate.members()) {
                taken.add(member.value());
                blocked.addAll(member.ancestors());
            }
            apply(root, namespace, candidate);
            made++;
        }
        return made;
    }

    private void apply(JsonObject root, String namespace, Candidate candidate) {
        String template;
        do {
            template = templatePrefix + base36(templateCounter++, 1);
        } while (usedNames.contains(template));
        usedNames.add(template);
        Def first = candidate.members().get(0);
        String base = baseOf(first.key());

        JsonObject body = first.value().deepCopy();
        Map<Integer, String> variableOf = new HashMap<>();
        List<String> overridden = new ArrayList<>();
        for (int i : candidate.varying()) {
            Leaf leaf = candidate.shape().get(i);
            if (leaf.depth() == 2) {
                overridden.add((String) leaf.path().get(0));
            } else {
                String variable = "$zq" + base36(variableCounter++, 1);
                variableOf.put(i, variable);
                set(body, leaf.path(), new JsonPrimitive(variable));
            }
        }
        for (String key : overridden) body.remove(key);
        root.add(base.isEmpty() ? template : template + "@" + base, body);

        for (Def member : candidate.members()) {
            JsonObject instance = new JsonObject();
            for (int i : candidate.varying()) {
                Leaf leaf = candidate.shape().get(i);
                JsonElement value = get(member.value(), leaf.path()).deepCopy();
                if (leaf.depth() == 2) instance.add((String) leaf.path().get(0), value);
                else instance.add(variableOf.get(i), value);
            }
            String key = nameOf(member.key()) + "@" + namespace + "." + template;
            replaceKeepingOrder(member.parent(), member.key(), member.value(), key, instance);
        }
    }

    // ─── walking ─────────────────────────────────────────────────────────────

    private static boolean isDef(String key, JsonElement value) {
        if (!value.isJsonObject()) return false;
        JsonObject object = value.getAsJsonObject();
        return object.has("type") || key.contains("@") || object.has("controls");
    }

    private static void collect(JsonElement element, List<JsonObject> ancestors, int depth, JsonObject unused, List<Def> out) {
        if (element.isJsonObject()) {
            JsonObject object = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
                String key = entry.getKey();
                JsonElement value = entry.getValue();
                if (isDef(key, value) && depth > 0) {
                    JsonObject def = value.getAsJsonObject();
                    out.add(new Def(key, def, object, List.copyOf(ancestors)));
                    List<JsonObject> next = new ArrayList<>(ancestors);
                    next.add(def);
                    collect(def, next, depth + 1, null, out);
                } else {
                    collect(value, ancestors, depth + (isDef(key, value) ? 1 : 0), null, out);
                }
            }
        } else if (element.isJsonArray()) {
            for (JsonElement item : element.getAsJsonArray()) collect(item, ancestors, depth, null, out);
        }
    }

    private static boolean isLeaf(JsonElement value) {
        if (value.isJsonPrimitive() || value.isJsonNull()) return true;
        if (!value.isJsonArray()) return false;
        for (JsonElement item : value.getAsJsonArray()) {
            if (item.isJsonObject() || item.isJsonArray()) return false;
        }
        return true;
    }

    /** The shape of a control: what must be equal for two controls to share a template. */
    private static String skeleton(JsonElement value, int depth, String property) {
        if (isLeaf(value)) {
            if (depth == 1) return "#";
            boolean reference = value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()
                    && value.getAsString().startsWith("$");
            if (property != null && VARIABLE_PROPERTIES.contains(property) && !reference) return "#";
            return "=" + GSON.toJson(value);
        }
        StringBuilder out = new StringBuilder();
        if (value.isJsonObject()) {
            out.append('{');
            for (Map.Entry<String, JsonElement> entry : value.getAsJsonObject().entrySet()) {
                out.append(GSON.toJson(entry.getKey())).append(':').append(skeleton(entry.getValue(), depth + 1, entry.getKey())).append(',');
            }
            return out.append('}').toString();
        }
        out.append('[');
        for (JsonElement item : value.getAsJsonArray()) out.append(skeleton(item, depth + 1, property)).append(',');
        return out.append(']').toString();
    }

    private static void leaves(JsonElement value, int depth, List<Object> path, List<Leaf> out) {
        if (isLeaf(value)) {
            out.add(new Leaf(List.copyOf(path), depth, value));
            return;
        }
        if (value.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : value.getAsJsonObject().entrySet()) {
                path.add(entry.getKey());
                leaves(entry.getValue(), depth + 1, path, out);
                path.remove(path.size() - 1);
            }
        } else {
            JsonArray array = value.getAsJsonArray();
            for (int i = 0; i < array.size(); i++) {
                path.add(i);
                leaves(array.get(i), depth + 1, path, out);
                path.remove(path.size() - 1);
            }
        }
    }

    private static JsonElement get(JsonElement value, List<Object> path) {
        for (Object step : path) {
            value = step instanceof Integer i ? value.getAsJsonArray().get(i) : value.getAsJsonObject().get((String) step);
        }
        return value;
    }

    private static void set(JsonElement value, List<Object> path, JsonElement leaf) {
        JsonElement parent = get(value, path.subList(0, path.size() - 1));
        Object last = path.get(path.size() - 1);
        if (last instanceof Integer i) parent.getAsJsonArray().set(i, leaf);
        else parent.getAsJsonObject().add((String) last, leaf);
    }

    private static void replaceKeepingOrder(JsonObject parent, String oldKey, JsonObject oldValue, String newKey, JsonElement newValue) {
        List<Map.Entry<String, JsonElement>> entries = new ArrayList<>(parent.entrySet());
        List<String> keys = new ArrayList<>(parent.keySet());
        for (String key : keys) parent.remove(key);
        for (Map.Entry<String, JsonElement> entry : entries) {
            if (entry.getKey().equals(oldKey) && entry.getValue() == oldValue) parent.add(newKey, newValue);
            else parent.add(entry.getKey(), entry.getValue());
        }
    }

    // ─── checking ────────────────────────────────────────────────────────────

    /** The file as the game will see it once every instance is resolved, without the templates. */
    private JsonObject expand(JsonObject root, String namespace) {
        Map<String, Map.Entry<String, JsonObject>> templates = new HashMap<>();
        JsonObject copy = root.deepCopy();
        for (String key : new ArrayList<>(copy.keySet())) {
            if (nameOf(key).startsWith(templatePrefix)) {
                templates.put(nameOf(key), Map.entry(key, copy.get(key).getAsJsonObject()));
                copy.remove(key);
            }
        }
        String marker = "@" + namespace + "." + templatePrefix;
        JsonElement current = copy;
        for (int round = 0; round < 64; round++) {
            String before = GSON.toJson(current);
            if (!before.contains(marker)) break;
            current = resolve(current, namespace, templates);
            if (GSON.toJson(current).equals(before)) break;
        }
        return current.getAsJsonObject();
    }

    private JsonElement resolve(JsonElement element, String namespace, Map<String, Map.Entry<String, JsonObject>> templates) {
        if (element.isJsonArray()) {
            JsonArray out = new JsonArray();
            for (JsonElement item : element.getAsJsonArray()) out.add(resolve(item, namespace, templates));
            return out;
        }
        if (!element.isJsonObject()) return element;
        JsonObject out = new JsonObject();
        String prefix = namespace + "." + templatePrefix;
        for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
            String key = entry.getKey();
            int at = key.indexOf('@');
            if (at > 0 && key.substring(at + 1).startsWith(prefix) && entry.getValue().isJsonObject()) {
                Map.Entry<String, JsonObject> template = templates.get(key.substring(at + 1 + namespace.length() + 1));
                if (template == null) return element;
                JsonObject instance = entry.getValue().getAsJsonObject();
                Map<String, JsonElement> variables = new HashMap<>();
                for (Map.Entry<String, JsonElement> e : instance.entrySet()) {
                    if (e.getKey().startsWith("$zq")) variables.put(e.getKey(), e.getValue());
                }
                JsonObject body = substitute(template.getValue().deepCopy(), variables).getAsJsonObject();
                for (Map.Entry<String, JsonElement> e : instance.entrySet()) {
                    if (!e.getKey().startsWith("$zq")) body.add(e.getKey(), e.getValue().deepCopy());
                }
                String base = baseOf(template.getKey());
                out.add(key.substring(0, at) + (base.isEmpty() ? "" : "@" + base), resolve(body, namespace, templates));
            } else {
                out.add(key, resolve(entry.getValue(), namespace, templates));
            }
        }
        return out;
    }

    private static JsonElement substitute(JsonElement element, Map<String, JsonElement> variables) {
        if (element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()) {
            JsonElement value = variables.get(element.getAsString());
            return value != null ? value.deepCopy() : element;
        }
        if (element.isJsonObject()) {
            JsonObject object = element.getAsJsonObject();
            for (String key : new ArrayList<>(object.keySet())) object.add(key, substitute(object.get(key), variables));
            return object;
        }
        if (element.isJsonArray() && !isLeaf(element)) {
            JsonArray array = element.getAsJsonArray();
            for (int i = 0; i < array.size(); i++) array.set(i, substitute(array.get(i), variables));
        }
        return element;
    }

    // ─── names ───────────────────────────────────────────────────────────────

    private static String nameOf(String key) {
        int at = key.indexOf('@');
        return at < 0 ? key : key.substring(0, at);
    }

    private static String baseOf(String key) {
        int at = key.indexOf('@');
        return at < 0 ? "" : key.substring(at + 1);
    }

    private static String base36(int value, int width) {
        StringBuilder out = new StringBuilder();
        do {
            out.insert(0, DIGITS.charAt(value % 36));
            value /= 36;
        } while (value > 0);
        while (out.length() < width) out.insert(0, '0');
        return out.toString();
    }

    private static int utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8).length;
    }

    private static JsonElement parse(String text) {
        JsonReader reader = new JsonReader(new StringReader(text));
        reader.setStrictness(Strictness.LENIENT);
        return JsonParser.parseReader(reader);
    }
}

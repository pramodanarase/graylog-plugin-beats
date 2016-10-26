/**
 * This file is part of Graylog Beats Plugin.
 * <p>
 * Graylog Beats Plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * Graylog Beats Plugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with Graylog Beats Plugin.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.beats;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import org.apache.commons.collections.map.LinkedMap;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.inputs.annotations.Codec;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.AbstractCodec;
import org.graylog2.plugin.inputs.codecs.MultiMessageCodec;
import org.graylog2.plugin.journal.RawMessage;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Inject;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.graylog.plugins.beats.MapUtils.flatten;

@Codec(name = "beats", displayName = "Beats")
public class BeatsCodec extends AbstractCodec implements MultiMessageCodec {
    private static final Logger LOG = LoggerFactory.getLogger(BeatsCodec.class);
    private static final String MAP_KEY_SEPARATOR = "_";
    private static final String DOUBLE_QUOTE = "\"";
    private static final String COMMA = ",";
    private static final String SPLIT_FILED_SEPARATOR = "---";
    private static final String COLON = ":";


    private final ObjectMapper objectMapper;

    @Inject
    public BeatsCodec(@Assisted Configuration configuration, ObjectMapper objectMapper) {
        super(configuration);
        this.objectMapper = requireNonNull(objectMapper);
    }

    @Nullable
    @Override
    public Message decode(@Nonnull RawMessage rawMessage) {
        LOG.info("inside decode()");
        final byte[] payload = rawMessage.getPayload();
        final Map<String, Object> event;
        try {
            event = objectMapper.readValue(payload, new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException e) {
            LOG.error("Couldn't decode raw message {}", rawMessage);
            return null;
        }

        return parseEvent(event);
    }

    @Nullable
    private Message parseEvent(Map<String, Object> event) {
        @SuppressWarnings("unchecked")
        final Map<String, String> metadata = (HashMap<String, String>) event.remove("@metadata");
        final String type;
        if (metadata == null) {
            LOG.warn("Couldn't recognize Beats type");
            type = "unknown";
        } else {
            type = metadata.get("beat");
        }
        final Message gelfMessage;
        switch (type) {
            case "filebeat":
                gelfMessage = parseFilebeat(event);
                break;
            case "topbeat":
                gelfMessage = parseTopbeat(event);
                break;
            case "packetbeat":
                gelfMessage = parsePacketbeat(event);
                break;
            case "winlogbeat":
                gelfMessage = parseWinlogbeat(event);
                break;
            default:
                LOG.debug("Unknown beats type {}. Using generic handler.", type);
                gelfMessage = parseGenericBeat(event);
                break;
        }

        return gelfMessage;
    }

    private Message createMessage(String message, Map<String, Object> event) {
        @SuppressWarnings("unchecked")
        final Map<String, Object> beat = (Map<String, Object>) event.remove("beat");
        final String hostname;
        final String name;
        if (beat == null) {
            hostname = "unknown";
            name = "unknown";
        } else {
            hostname = String.valueOf(beat.get("hostname"));
            name = String.valueOf(beat.get("name"));
        }
        final String timestampField = String.valueOf(event.remove("@timestamp"));
        final DateTime timestamp = Tools.dateTimeFromString(timestampField);
        final String type = String.valueOf(event.get("type"));
        final Object tags = event.get("tags");

        final Message result = new Message(message, hostname, timestamp);
        result.addField("name", name);
        result.addField("type", type);
        result.addField("tags", tags);

        return result;
    }

    /**
     * @see <a href="https://www.elastic.co/guide/en/beats/filebeat/1.2/exported-fields.html">Filebeat Exported Fields</a>
     */
    private Message parseFilebeat(Map<String, Object> event) {
        final String message = String.valueOf(event.get("message"));
        final Message gelfMessage = createMessage(message, event);
        gelfMessage.addField("facility", "filebeat");
        gelfMessage.addField("file", event.get("source"));
        gelfMessage.addField("input_type", event.get("input_type"));
        gelfMessage.addField("count", event.get("count"));
        gelfMessage.addField("offset", event.get("offset"));
        @SuppressWarnings("unchecked")
        final Map<String, Object> fields = (Map<String, Object>) event.get("fields");
        if (fields != null) {
            gelfMessage.addFields(fields);
        }
        return gelfMessage;
    }

    /**
     * @see <a href="https://www.elastic.co/guide/en/beats/topbeat/1.2/exported-fields.html">Topbeat Exported Fields</a>
     */
    private Message parseTopbeat(Map<String, Object> event) {
        final Message gelfMessage = createMessage("-", event);
        gelfMessage.addField("facility", "topbeat");
        final Map<String, Object> flattened = flatten(event, "topbeat", MAP_KEY_SEPARATOR);

        // Fix field names containing dots, like "cpu.name"
        final Map<String, Object> withoutDots = MapUtils.replaceKeyCharacter(flattened, '.', MAP_KEY_SEPARATOR.charAt(0));
        gelfMessage.addFields(withoutDots);
        return gelfMessage;
    }

    /**
     * @see <a href="https://www.elastic.co/guide/en/beats/packetbeat/1.2/exported-fields.html">Packetbeat Exported Fields</a>
     */
    private Message parsePacketbeat(Map<String, Object> event) {
        final Message gelfMessage = createMessage("-", event);
        gelfMessage.addField("facility", "packetbeat");
        final Map<String, Object> flattened = flatten(event, "packetbeat", MAP_KEY_SEPARATOR);

        // Fix field names containing dots, like "icmp.version"
        final Map<String, Object> withoutDots = MapUtils.replaceKeyCharacter(flattened, '.', MAP_KEY_SEPARATOR.charAt(0));
        gelfMessage.addFields(withoutDots);

        return gelfMessage;
    }

    /**
     * @see <a href="https://www.elastic.co/guide/en/beats/winlogbeat/1.2/exported-fields.html">Winlogbeat Exported Fields</a>
     */
    private Message parseWinlogbeat(Map<String, Object> event) {
        final String message = String.valueOf(event.remove("message"));
        final Message gelfMessage = createMessage(message, event);
        gelfMessage.addField("facility", "winlogbeat");
        final Map<String, Object> flattened = flatten(event, "winlogbeat", MAP_KEY_SEPARATOR);

        // Fix field names containing dots, like "user.name"
        final Map<String, Object> withoutDots = MapUtils.replaceKeyCharacter(flattened, '.', MAP_KEY_SEPARATOR.charAt(0));
        gelfMessage.addFields(withoutDots);
        return gelfMessage;
    }

    private Message parseGenericBeat(Map<String, Object> event) {
        final String message = String.valueOf(event.remove("message"));
        final Message gelfMessage = createMessage(message, event);
        gelfMessage.addField("facility", "genericbeat");
        final Map<String, Object> flattened = flatten(event, "beat", MAP_KEY_SEPARATOR);

        // Fix field names containing dots
        final Map<String, Object> withoutDots = MapUtils.replaceKeyCharacter(flattened, '.', MAP_KEY_SEPARATOR.charAt(0));
        gelfMessage.addFields(withoutDots);
        return gelfMessage;
    }

    @Nullable
    @Override
    public Collection<Message> decodeMessages(@Nonnull RawMessage rawMessage) {
        LOG.info(" inside decodeMessages" + rawMessage);
        Collection<Message> messages = new ArrayList<>();
        String splitFiled = null;
        Object message = null;
        Object messageSplit = null;
        Object messageSplitList = null;
        boolean isJson = false;
        boolean isSplitFieldInMessage = false;

        final byte[] payload = rawMessage.getPayload();
        final Map<String, Object> event;
        try {
            event = objectMapper.readValue(payload, new TypeReference<Map<String, Object>>() {
            });
            if (LOG.isDebugEnabled()) {
                for (Object s : event.entrySet().toArray()) {
                    LOG.debug("event filed  {} of type {}", s.toString(), s.getClass());
                }
            }

            /**
             * 1 . Check json & get splitted filed
             * fields={gl2_source_collector=MyLocalENV, splitFiled=metric}
             */

            message = event.get("message");
            if (message instanceof String) {
                if (((String) message).matches("^\\{.*\\}$")) {
                    isJson = true;
                    splitFiled = getSplitField(event);
                }
            }

            /**
             * 2. get message from event.get("message") and update message for each splited field;
             * check split filed is present
             */
            Map messageMap = null;
            if (StringUtils.isNotEmpty(splitFiled) && isJson) {
                String[] splitFiledArr = splitFiled.split(SPLIT_FILED_SEPARATOR);
                messageMap = convertMessageToMap((String) message);
                for (String sf : splitFiledArr) {
                    if (messageMap.containsKey(sf)) {
                        isSplitFieldInMessage = true;
                        splitFiled = sf ;
                        LOG.debug(" spliting message on {}", splitFiled);
                        break;
                    }
                }
            }

            /**
             * 3. if split is true , split the message
             */
                if (isSplitFieldInMessage) {
                    //message = event.remove("message");
                    Object beatObj = event.get("beat");
                    Object timestampObj = event.get("@timestamp");
                    Object metadataObj = event.get("@metadata");
                    messageSplit = messageMap.remove(splitFiled);
                    if (messageSplit instanceof ArrayList) {
                        ArrayList splitList = (ArrayList) messageSplit;
                        LOG.debug("Nested Json size are", splitList.size());
                        for (Object value : splitList) {
                            messageMap.put(splitFiled, value);
                            event.put("message", convertMaptoJson(messageMap));
                            event.put("beat", beatObj);
                            event.put("@timestamp", timestampObj);
                            event.put("@metadata", metadataObj);
                            messages.add(parseEvent(event));
                        }
                    }

                } else {
                    LOG.debug(" {} field not present", splitFiled);
                    messages.add(parseEvent(event));
                }

    } catch(IOException e){
        LOG.error("Couldn't decode raw message {}", rawMessage);
        return null;
    }

    return messages;
}

    private String getSplitField(Map<String, Object> event) {
        String splitFiled = null;
        /**
         * 1 . Check it contain splitfiled in fileds
         * fields={gl2_source_collector=MyLocalENV, splitFiled=metric}
         */
        if (event != null && event.containsKey("fields")) {
            Object splitFieldObj = event.get("fields");
            if (splitFieldObj instanceof Map) {
                Map splitMap = (Map) splitFieldObj;
                if (splitMap.containsKey("splitFiled")) {
                    splitFiled = (String) splitMap.get("splitFiled");
                    LOG.debug("splitFiled is {}", splitFiled);
                }
            }
        }
        return splitFiled;
    }

    private StringBuffer addDoubleQuoteToString(String value) {
        StringBuffer buffer = new StringBuffer(DOUBLE_QUOTE);
        return value == null ? null : buffer.append(value).append(DOUBLE_QUOTE);
    }

    private String convertMaptoJson(Map messageMap) {
        StringBuffer buffer = new StringBuffer();
        buffer.append("{");
        for (Object key : messageMap.keySet()) {
            Object value = messageMap.get(key);
            buffer.append(addDoubleQuoteToString((String) key));
            buffer.append(COLON);
            if (value instanceof String) {
                buffer.append(addDoubleQuoteToString((String) value));

            } else if (value instanceof Map) {
                Map valmap = (Map) value;
                buffer.append("{");
                for (Object k : valmap.keySet()) {
                    Object v = valmap.get(k);
                    buffer.append(addDoubleQuoteToString((String) k));
                    buffer.append(COLON);
                    if (v instanceof String) {
                        buffer.append(addDoubleQuoteToString((String) v));
                    } else {
                        buffer.append(v);
                    }
                    buffer.append(COMMA);
                }
                buffer.replace(buffer.length() - 1, buffer.length(), "");
                buffer.append("}");
            } else {
                buffer.append(value);
            }
            buffer.append(COMMA);
        }
        buffer.replace(buffer.length() - 1, buffer.length(), "");
        buffer.append("}");

        return buffer.toString();

    }

    private void checkNumber(StringBuffer buffer, String value) {
        try {
            double d = Double.parseDouble(value);
            buffer.append(d);
        } catch (Exception exe) {
            buffer.append(addDoubleQuoteToString(value));

        }
    }


    private Map convertMessageToMap(String message) {
        Map<String, Object> messageMap = new LinkedMap();
        try {
            messageMap = objectMapper.readValue(message, new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException e) {
            LOG.error("Couldn't decode raw message {}", message);
        }
        return messageMap;
    }


@FactoryClass
public interface Factory extends AbstractCodec.Factory<BeatsCodec> {
    @Override
    BeatsCodec create(Configuration configuration);

    @Override
    Config getConfig();

    @Override
    Descriptor getDescriptor();
}

@ConfigClass
public static class Config extends AbstractCodec.Config {
}


public static class Descriptor extends AbstractCodec.Descriptor {
    @Inject
    public Descriptor() {
        super(BeatsCodec.class.getAnnotation(Codec.class).displayName());
    }
}
}

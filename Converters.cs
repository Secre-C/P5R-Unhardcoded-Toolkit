using System.Text.Json;
using System.Text.Json.Serialization;

namespace Unhardcoded_P5R;
public class HexStringJsonConverter : JsonConverter<uint>
{
    public override void Write(Utf8JsonWriter writer, uint value, JsonSerializerOptions options)
    {
        writer.WriteStringValue($"0x{value:x}");
    }

    public override uint Read(ref Utf8JsonReader reader, Type objectType, JsonSerializerOptions options)
    {
        var str = reader.GetString();
        if (str == null || !str.StartsWith("0x"))
            throw new Exception();
        return uint.Parse(str.Substring(2), System.Globalization.NumberStyles.HexNumber);
    }
}

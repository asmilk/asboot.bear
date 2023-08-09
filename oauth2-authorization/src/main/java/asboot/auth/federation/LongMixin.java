package asboot.auth.federation;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class LongMixin {
	
	@JsonProperty("long")
	Long value;

}

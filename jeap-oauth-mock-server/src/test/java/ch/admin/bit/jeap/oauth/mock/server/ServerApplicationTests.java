package ch.admin.bit.jeap.oauth.mock.server;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ServerApplicationTests {

	@Test
	@SuppressWarnings("java:S2699")
		// Just checking that the context loads here
	void contextLoads() {
	}

}

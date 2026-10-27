import { describe, expect, it } from "vitest";
import { maskSecrets } from "./util";

describe("maskSecrets", () => {
  it("скрывает пароли, токены и заголовки авторизации в технических текстах", () => {
    expect(maskSecrets("password=Sup3rSecret&user=bob")).toBe("password=••••&user=bob");
    expect(maskSecrets("Authorization: Bearer abc.def.ghi")).toBe("Authorization: Bearer ••••");
    expect(maskSecrets("ftp://admin:hunter2@192.0.2.5/")).toBe("ftp://admin:••••@192.0.2.5/");
    expect(maskSecrets('{"api_key": "k-123"}')).toContain("••••");
    expect(maskSecrets("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----")).not.toContain("MIIE");
  });
  it("не трогает обычный баннер и пустые значения", () => {
    expect(maskSecrets("SSH-2.0-OpenSSH_9.6")).toBe("SSH-2.0-OpenSSH_9.6");
    expect(maskSecrets("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49")).toBe("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49");
    expect(maskSecrets("")).toBe("");
  });
});

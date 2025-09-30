import base64

ASM_ISSUES_API_RESPONSE = {
    "success": True,
    "message": "Search completed!",
    "result": {
        "timed_out": False,
        "more": True,
        "total_pages": 200,
        "hits": [
            {
                "id": "00102ce77683084de663792fc8b433bba30d9180a0638d602b6441c579d7e66d",
                "uid": "00102ce77683084de663792fc8b433bba30d9180a0638d602b6441c579d7e66d",
                "uuid": "7d26ae2e-bbbf-4d43-b709-d8dfb21ff9f6",
                "description": "A cookie was found, missing the 'HttpOnly' attribute. HttpOnly is a flag included in a Set-Cookie HTTP response header. Using the HttpOnly flag when generating a cookie helps mitigate the risk of client side script accessing the protected cookie.",
                "dynamic_id": 21119403,
                "name": "insecure_cookie_httponly_attribute",
                "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                "upstream": "intrigue",
                "last_seen": "2020-07-14T15:18:51.000Z",
                "first_seen": "2020-06-29T00:46:43.000Z",
                "entity_uid": "26b14faf40c7ab30f955b539e9b173c44ac2413f54cfc52103753ca8b21cc7ce",
                "entity_type": "Intrigue::Entity::Uri",
                "entity_name": "https://advertising.amazon.ca:443",
                "alias_group": "1467",
                "collection": "amazon",
                "collection_uuid": "53ece40b-d2ea-465d-82ad-216539c2dc3f",
                "collection_type": "pre_collection",
                "organization_uuid": None,
                "summary": {
                    "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                    "severity": 5,
                    "scoped": True,
                    "confidence": "confirmed",
                    "status": "closed_no_repro",
                    "category": "application",
                    "identifiers": None,
                    "status_new": "closed",
                    "status_new_detailed": "no_repro",
                    "ticket_list": None,
                },
                "tags": [],
                "cisa_known_exploited": None,
                "epss_v2_score_lte": None,
                "epss_v2_percentile_gte": None,
            },
            {
                "id": "7b6b31706c023d2a81e55440b6dacbeb331336711bc8373c7053019e8a27d431",
                "uid": "7b6b31706c023d2a81e55440b6dacbeb331336711bc8373c7053019e8a27d431",
                "uuid": "065e5afe-2a1c-49f9-bc7f-c2ba98c0f312",
                "description": "A cookie was found, missing the 'HttpOnly' attribute. HttpOnly is a flag included in a Set-Cookie HTTP response header. Using the HttpOnly flag when generating a cookie helps mitigate the risk of client side script accessing the protected cookie.",
                "dynamic_id": 15856601,
                "name": "insecure_cookie_httponly_attribute",
                "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                "upstream": "intrigue",
                "last_seen": "2020-07-14T15:18:51.000Z",
                "first_seen": "2020-06-29T00:46:43.000Z",
                "entity_uid": "124443764c3426acf71ef2ccc91b7eb34d98f94820095a2826be006d0c7ca3dd",
                "entity_type": "Intrigue::Entity::Uri",
                "entity_name": "http://buy.amazon.com:80",
                "alias_group": "1383",
                "collection": "amazon",
                "collection_uuid": "53ece40b-d2ea-465d-82ad-216539c2dc3f",
                "collection_type": "pre_collection",
                "organization_uuid": None,
                "summary": {
                    "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                    "severity": 5,
                    "scoped": True,
                    "confidence": "confirmed",
                    "status": "open_new",
                    "category": "application",
                    "identifiers": None,
                    "status_new": "open",
                    "status_new_detailed": "new",
                    "ticket_list": None,
                },
                "tags": [],
                "cisa_known_exploited": None,
                "epss_v2_score_lte": None,
                "epss_v2_percentile_gte": None,
            },
            {
                "id": "7d0cbfca575158ced1561d17484257e20ab7ea854ec3d0745d7022613f448eb3",
                "uid": "7d0cbfca575158ced1561d17484257e20ab7ea854ec3d0745d7022613f448eb3",
                "uuid": "a2c2baa8-26f6-4da2-b8a3-3b9d8d48e4fc",
                "description": "A cookie was found, missing the 'secure' attribute",
                "dynamic_id": 21215409,
                "name": "insecure_cookie_httponly_attribute",
                "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                "upstream": "intrigue",
                "last_seen": "2020-07-14T15:18:51.000Z",
                "first_seen": "2020-06-29T00:46:43.000Z",
                "entity_uid": "db14144c53a8d0c93c0eec5c6b140433ce332374381c0b597aa2d9a14d95077a",
                "entity_type": "Intrigue::Entity::Uri",
                "entity_name": "https://cc.amazon.com:443",
                "alias_group": "1474",
                "collection": "amazon",
                "collection_uuid": "53ece40b-d2ea-465d-82ad-216539c2dc3f",
                "collection_type": "pre_collection",
                "organization_uuid": None,
                "summary": {
                    "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                    "severity": 5,
                    "scoped": True,
                    "confidence": "confirmed",
                    "status": "open_new",
                    "category": "application",
                    "identifiers": None,
                    "status_new": "open",
                    "status_new_detailed": "new",
                    "ticket_list": None,
                },
                "tags": [],
                "cisa_known_exploited": None,
                "epss_v2_score_lte": None,
                "epss_v2_percentile_gte": None,
            },
            {
                "id": "e2462f7b9b957547593e93521c737447fcb58cf2edcaad03c55d3d6d551bd1e1",
                "uid": "e2462f7b9b957547593e93521c737447fcb58cf2edcaad03c55d3d6d551bd1e1",
                "uuid": "8bfea273-9857-465f-9b1a-4bd1a0314b8b",
                "description": "A cookie was found, missing the 'secure' attribute",
                "dynamic_id": 16085842,
                "name": "insecure_cookie_secure_attribute",
                "pretty_name": "Insecure Cookie (Missing 'Secure' Attribute)",
                "upstream": "intrigue",
                "last_seen": "2020-07-14T15:18:51.000Z",
                "first_seen": "2020-06-29T00:46:43.000Z",
                "entity_uid": "26b14faf40c7ab30f955b539e9b173c44ac2413f54cfc52103753ca8b21cc7ce",
                "entity_type": "Intrigue::Entity::Uri",
                "entity_name": "https://advertising.amazon.ca:443",
                "alias_group": "1467",
                "collection": "amazon",
                "collection_uuid": "53ece40b-d2ea-465d-82ad-216539c2dc3f",
                "collection_type": "pre_collection",
                "organization_uuid": None,
                "summary": {
                    "pretty_name": "Insecure Cookie (Missing 'Secure' Attribute)",
                    "severity": 5,
                    "scoped": True,
                    "confidence": "confirmed",
                    "status": "open_new",
                    "category": "application",
                    "identifiers": None,
                    "status_new": "open",
                    "status_new_detailed": "new",
                    "ticket_list": None,
                },
                "tags": [],
                "cisa_known_exploited": None,
                "epss_v2_score_lte": None,
                "epss_v2_percentile_gte": None,
            },
        ],
        "page": 0,
        "page_size": 50,
        "total_hits": 10000,
        "next_page_token": "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIn0.yb-CKoy0ixZ_NJ09iV8PazK8dCstWFwSu5UKF_37qgdaNhLYzzQ7FA.XVKUzQzbqEYyl9GH.C_souB36B36ozYC1BFDv_lfMO3LTFYWewZdH4ZJKAcI_yeI5C8of71BfWs24--wV4dDNMQTf4AvY8joW_1fVSwTayNVTLheyuQDtbM0k7RoALhHmTl7uPFkL7uUBNkcZK8S_rTAxTgEIE4iZY79yXb8KA7NKteIA8jnxVxIEgUMAM5ksdbp7jIlY_yp31O010nnWqhQeqB3wX_2vVJJUDYpwpEfXm6B2hJ8ub3H0DpU19Qqvq7n6j7wphNm5HAfe_DJgqnImdal6fgqqU8MmElxm6NmIOHiMXLqT_eQNGU6zWMEoSMBYUVoIvldiTVYUY4fZbPWZD81ZSu-6KC0BzD3_A8VC-tGE94GGITIUsqfZjJ0tXCTRdwqJ7o89mVlyZlW3obzjJPHLV76qeG6iYg7HukP6NqwweWHpCJ1LcwpiSbMmlUILqA1aH0A4n6ME9gKGGTad3UHhbzOqCJJfIfWpbv2kEg0ru10RqepJzbpKO05mmm_T6YxIbtrr_RVcEkDsrOxJDlPWxTVpJvMHjjZNEHT0tum-MNadIv5qLRUBM68SKf309TeH__8lbhthNlqPTKH-WOWEcW5oU2kYjaEKq_jG4OwhVtUCdxrt8_FlFboUVvtbc1HT03iZ2EwO8f7IgXJc1JExk16CMp4b81CexJuJkAR7ZxyvbO_4FY0KgTbYAGxm1rwU2OgQ9KbMiGrE2vhNriauEmRFYXOm3TD-sqahCLjO4vM1u5ScLrfUuJV46-_yfIuMOAxFH8TXcxqyAdWqZPmVk6Br-b4Ze1IJICLK_mvZNzW1QkEOqIar2-VLZHcpS2bL9SM8bxbqzIy9ymOCbkfoSClMyK5QfJeYW3_icdIXtD3d71YX6khxjt-EC9PvOraRO_-R1uUggI2kCnOPEdbolE8R.Sgv3BmgPx_AoDxgNXtC9PQ",
    },
}

DTM_ALERTS_API_RESPONSE = {
    "alerts": [
        {
            "id": "d2e9sqjco5vu4if1ct70",
            "monitor_id": "d08auehgkipgjt1puc9g",
            "doc": {
                "__id": "47196b63-5031-4a50-b09d-22a76f46f7b1",
                "__type": "message",
                "body": "🐲😢😏🫨🫨🇲🇼🫢➿😑😨🫡\n\n😨😰🫡😬😟🤫😱😢\n\n✅ Top Direct SMM Panel Provider!\n\n✅ 5,000+ Services Across Various Social Media Platforms!\n\n✅ Best Prices in the Market!\n\n✅ 24/7 Customer Support\n\n- - - - - - - - - - - -\n\nWe provide services almost for all social medias! \nFacebook, YouTube, TikTok, Telegram, Twitter, Reddit, SoundCloud 59+ more...\n\n🫢➿😃🫨😨😑😬\n🫨😨😬😬😱🫨😏\n\nOur panel has most popular payment methods such as:\n\n💳 PayPal\n\n💰 CryptoCurrency\n\n💳 Credit Cards\n\n5 more..\n\n💲 Minimum Deposit: 1$\n\n🇲🇼😎😬🫢🫡🫨🇲🇼\n🇲🇼🫢➿😑😨🫡🇲🇼\n\n\nYou can easily buy a SMM Panel with all of our services in hours!\n\n✅Full access to admin panel\n✅All services will be automatically inserted & updated on your panel!\n✅Set your own prices by setting your desired % profit\n✅ Own your SMM Panel at a low cost!\n\nSTART EARNING MONEY TODAY!\n\n😏😨😥😕🫢😎😨😏\n\nOur prices are unbeatable since we are direct providers, here are few examples:\n\n🖼 Instagram Followers - 0.14$ per 1k\n\n🖼 Instagram Post Likes - 0.03$ per 1k\n\n🖼 TikTok Followers - 1.5$ per 1k\n\n🖼 TikTok Views - 0.0003$ per 1k\n\n🖼 TikTok Likes - 0.15$ per 1k\n\n4,999... more\n\n😥😨🫢😱😥😬😏\n\n🌐 Facebook Reports ▫️\n\n🖼 Telegram Group Reports ▫️\n\n🕊 Twitter Reports ▫️\n\n🟥 YouTube Reports ▫️\n\n🤖 Android / IOS Application Reports ▫️\n\n👋 Fiver Reports ▫️\n\n🌍 Personal/Developer Proxy (HTTP/SOCKS)\n\n🤖 Application Installs & Reviews\n\n📨 Mass DM for Discord, Telegram, Twitter, Instagram and more!\n\n⚠️ WE CAN NOT WAIT TO SEE YOU SUCCEED ⚠️\n\n\n💲 Start your own business NOW!\n\n🔗 https://smmzilla.org\n🔗 https://smmzilla.org\n🔗 https://smmzilla.org\n\n Prem, Instagram, Ad, Session, Growth, Hack, Advertising, Aged Tokens, Dm, Code, Snapchat, Adbot, Facebook, Marketing, Ads, Telegram-Premium, Panel, Source, Marketing, Aged Account, Crypto, Tg Adbot, Promotion, Fresh, Market, Logs, Advertising bot, Online, Gift Card, Telegram, Massive, Accounts, Coding, Smm, Adv, Hacking, Tg Prem, Offline, Advertise, Marketing Mass Giftcard, Bot, Tdata, Code, Advert, Advertising, Growth, Hack",
                "channel": {
                    "channel_id": "-1001354051262",
                    "channel_info": {"description": "👨‍💻Methsauce👨‍💻"},
                    "channel_url": "https://t.me/methsauce",
                    "invite_url": "https://t.me/methsauce",
                    "messenger": {"id": "telegram", "name": "Telegram"},
                    "name": "methsauce",
                },
                "ingested": "2025-08-13T06:37:08Z",
                "message_id": "2086406193152",
                "messenger": {"id": "telegram", "name": "Telegram"},
                "sender": {
                    "identity": {"first_name": "Yftf Ygg", "name": "Yftf Ygg "},
                    "telegram": {"user_id": 8315819405},
                },
                "source": "vanellope",
                "timestamp": "2025-08-13T06:37:05Z",
            },
            "label_matches": [],
            "doc_matches": [
                {
                    "match_path": "body",
                    "locations": [
                        {"offsets": [562, 566], "value": "full"},
                        {"offsets": [567, 573], "value": "access"},
                    ],
                    "match_field": "full access",
                }
            ],
            "tags": [],
            "created_at": "2025-08-13T14:15:41.786Z",
            "updated_at": "2025-08-13T14:15:45.818Z",
            "labels_url": "https://api.intelligence.mandiant.com/v4/dtm/docs/message/ad174e82-7a1d-4d4d-8a20-34a54f077f5b/labels",
            "topics_url": "https://api.intelligence.mandiant.com/v4/dtm/docs/message/ad174e82-7a1d-4d4d-8a20-34a54f077f5b/topics",
            "doc_url": "https://api.intelligence.mandiant.com/v4/dtm/docs/message/ad174e82-7a1d-4d4d-8a20-34a54f077f5b",
            "status": "new",
            "alert_type": "Message",
            "alert_summary": "Top Direct SMM Panel Provider 5,000 Services Across Various Social Media Platforms Best Prices in the Market 24 7 Customer Support We provide services almost for all social medias Facebook YouTube TikTok Telegram Twitter Reddit SoundCloud 59 more Our pane…",
            "title": 'Found topic "facebook" posted by actor "Yftf Ygg " on Telegram channel "methsauce"',
            "email_sent_at": "",
            "indicator_mscore": 50,
            "severity": "low",
            "confidence": 0.2565609101122806,
            "aggregated_under_id": "d2c25trgk0gc73cc0ms0",
            "has_analysis": bool(False),
            "ai_doc_summary": 'This message advertises a "Top Direct SMM Panel Provider" offering a wide range of social media services, including fake engagement metrics and potentially malicious services like application installs/reviews and mass DMs, all at extremely low prices. The advertised services and techniques present potential risks, including amplification of disinformation, account compromise via malicious applications, and circumvention of platform security measures.',
            "similarity_score": 0.9514825,
            "ignore": bool(False),
            "monitor_version": 1,
        },
        {
            "id": "d2e9s1su9n23r7f74og0",
            "monitor_id": "d08auehgkipgjt1puc9g",
            "tags": [],
            "created_at": "2025-08-13T14:15:35.686Z",
            "updated_at": "2025-08-13T14:15:37.915Z",
            "labels_url": "https://api.intelligence.mandiant.com/v4/dtm/docs/message/268903fa-2220-4410-8df5-693d99bd971f/labels",
            "topics_url": "https://api.intelligence.mandiant.com/v4/dtm/docs/message/268903fa-2220-4410-8df5-693d99bd971f/topics",
            "doc_url": "https://api.intelligence.mandiant.com/v4/dtm/docs/message/268903fa-2220-4410-8df5-693d99bd971f",
            "status": "new",
            "alert_type": "Message",
            "alert_summary": "Top Direct SMM Panel Provider 5,000 Services Across Various Social Media Platforms Best Prices in the Market 24 7 Customer Support We provide services almost for all social medias Facebook YouTube TikTok Telegram Twitter Reddit SoundCloud 59 more Our pane…",
            "title": 'Found topic "facebook" posted by actor "Hsh Jjw" on Telegram channel "MoneyMakingMethodz"',
            "email_sent_at": "",
            "indicator_mscore": 50,
            "severity": "low",
            "confidence": 0.2565609101122806,
            "aggregated_under_id": "d2c25trgk0gc73cc0ms0",
            "has_analysis": bool(False),
            "ai_doc_summary": "This message advertises an SMM (Social Media Marketing) panel service, providing options to artificially inflate metrics across various social media platforms, potentially indicating a source for fake engagement and influence operations. The service also offers methods to report accounts on social media platforms. It also offers methods to mass DM users on various platforms, and to distribute applications.",
            "similarity_score": 0.9438503,
            "ignore": bool(False),
            "monitor_version": 1,
        },
    ]
}

IOC_STREAM_API_RESPONSE = {
    "data": [
        {
            "id": "4c80542e8806fa18f2e6d0b46fa703b772ab3198e19362539eaad2608b184caf",
            "type": "file",
            "links": {
                "self": "https://www.virustotal.com/api/v3/files/4c80542e8806fa18f2e6d0b46fa703b772ab3198e19362539eaad2608b184caf"
            },
            "attributes": {
                "last_modification_date": 1755155372,
                "last_submission_date": 1755155019,
                "sha1": "ae6c29120d898ca67f25f9c33b45679dc9bdb9ab",
                "meaningful_name": "_4c80542e8806fa18f2e6d0b46fa703b772ab3198e19362539eaad2608b184caf.elf",
                "available_tools": [],
                "first_submission_date": 1755154554,
                "telfhash": "t129e0ab04be318a2888cb5b70fd6d0374a511132116628710cf60c7e0543f058a30ee8a",
                "unique_sources": 2,
                "reputation": -12,
                "tlsh": "T1AF4319457D918A2AC6E413B6B77F42AD332163B9E2CB3313D8140B587A8B45F4F67B81",
                "downloadable": bool(True),
                "size": 60076,
                "md5": "23e928bb28a5c0b2981523d06b261199",
                "vhash": "092ac2abc8211f80b6dda09de8a244c1",
                "magic": "ELF 32-bit LSB executable, ARM, EABI4 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, with debug_info, not stripped",
                "times_submitted": 2,
                "last_analysis_stats": {
                    "malicious": 18,
                    "suspicious": 0,
                    "undetected": 36,
                    "harmless": 0,
                    "timeout": 11,
                    "confirmed-timeout": 0,
                    "failure": 0,
                },
                "gti_assessment": {
                    "gti_confidence_score": 90,
                    "associated_malware_configuration": bool(True),
                    "malicious_sandbox_verdict": bool(True),
                    "threat_score": {"value": 30},
                    "severity": {"value": "SEVERITY_LOW"},
                    "description": "This indicator is malicious (low severity). It was detected by sandbox analysis, indicating suspicious behavior, contains known malware configurations, it is contained within a collection provided by the Google Threat Intelligence team, or a trusted partner or security researcher and analysis confirms configuration consistent with a well-known malware family.",
                },
            },
        }
    ],
    "meta": {
        "cursor": "eJwNzNFugyAUgOFXQohLb2eUNV0OBgWOctfariK0waWNSvbw8-K__P4_24Xva4gvfMYzch4VjcVAwls-g4MsLuiveNNhvtDQNv6kWwzsjLDVXfCSeGpY5EBybbqxNhX_UKZpdj-3XRSmMkx18fems9mycLqUVf5zXCmw9QBqyISq9vpcHNeD_YIECEygJpAa1yN3kIwHZRyU97wuZYJpWKwqvEU-AvaZnTQR6nOBVDzsY39RufVqdGKCDab72st_P3BLUg==",
        "count": 2545,
    },
    "links": {
        "self": "https://www.virustotal.com/api/v3/ioc_stream",
        "next": "https://www.virustotal.com/api/v3/ioc_stream?cursor=eJwNzNFugyAUgOFXQohLb2eUNV0OBgWOctfariK0waWNSvbw8-K__P4_24Xva4gvfMYzch4VjcVAwls-g4MsLuiveNNhvtDQNv6kWwzsjLDVXfCSeGpY5EBybbqxNhX_UKZpdj-3XRSmMkx18fems9mycLqUVf5zXCmw9QBqyISq9vpcHNeD_YIECEygJpAa1yN3kIwHZRyU97wuZYJpWKwqvEU-AvaZnTQR6nOBVDzsY39RufVqdGKCDab72st_P3BLUg%3D%3D",
    },
}

THREAT_LIST_API_RESPONSE = {
    "iocs": [
        {
            "data": {
                "type": "file",
                "id": "0002df2e11c8899082cebc20a39df5ce78bb3b5be2da9f1285b9026ea648ef60",
                "attributes": {
                    "gti_assessment": {
                        "verdict": {"value": "VERDICT_MALICIOUS"},
                        "threat_score": {"value": 30},
                        "severity": {"value": "SEVERITY_LOW"},
                    },
                    "creation_date": 1300161967,
                    "first_submission_date": 1755144099,
                    "last_analysis_date": 1755144099,
                    "last_analysis_stats": {
                        "malicious": 59,
                        "undetected": 14,
                        "typeUnsupported": 4,
                    },
                    "last_modification_date": 1755151347,
                    "last_submission_date": 1755144099,
                    "md5": "7d85adc3702eb303bb56456801d47b92",
                    "meaningful_name": "/scratch/zoo/2025/08/14/7d85adc3702eb303bb56456801d47b92",
                    "names": [
                        "/scratch/zoo/2025/08/14/7d85adc3702eb303bb56456801d47b92"
                    ],
                    "positives": 59,
                    "tags": ["overlay", "spreader", "peexe"],
                    "times_submitted": 1,
                    "type_tags": ["pe", "peexe", "win32", "windows", "executable"],
                    "vhash": "04403d1d1e7az131afz23z2fz",
                },
                "relationships": {},
            }
        },
        {
            "data": {
                "type": "file",
                "id": "00049fb3e2a8eeee2db6f63b6a6a6f842af3a323c3b019ced8b6e804b822c645",
                "attributes": {
                    "gti_assessment": {
                        "verdict": {"value": "VERDICT_MALICIOUS"},
                        "threat_score": {"value": 30},
                        "severity": {"value": "SEVERITY_LOW"},
                    },
                    "creation_date": 1300161967,
                    "first_submission_date": 1755144099,
                    "last_analysis_date": 1755144099,
                    "last_analysis_stats": {
                        "malicious": 59,
                        "undetected": 14,
                        "typeUnsupported": 4,
                    },
                    "last_modification_date": 1755151347,
                    "last_submission_date": 1755144099,
                    "md5": "7d85adc3702eb303bb56456801d47b92",
                    "meaningful_name": "/scratch/zoo/2025/08/14/7d85adc3702eb303bb56456801d47b92",
                    "names": [
                        "/scratch/zoo/2025/08/14/7d85adc3702eb303bb56456801d47b92"
                    ],
                    "positives": 59,
                    "tags": ["overlay", "spreader", "peexe"],
                    "times_submitted": 1,
                    "type_tags": ["pe", "peexe", "win32", "windows", "executable"],
                    "vhash": "04403d1d1e7az131afz23z2fz",
                },
                "relationships": {},
            }
        },
        {
            "data": {
                "type": "file",
                "id": "001291efca2c8020caac3267bd5977fa8065562062ffa815c00e584a84f4d0bd",
                "attributes": {
                    "gti_assessment": {
                        "verdict": {"value": "VERDICT_MALICIOUS"},
                        "threat_score": {"value": 30},
                        "severity": {"value": "SEVERITY_LOW"},
                    },
                    "creation_date": 1300161967,
                    "first_submission_date": 1755143618,
                    "last_analysis_date": 1755143618,
                    "last_analysis_stats": {
                        "malicious": 58,
                        "undetected": 15,
                        "typeUnsupported": 4,
                    },
                    "last_modification_date": 1755150861,
                    "last_submission_date": 1755143618,
                    "md5": "d949c0203fff19b3216486820e81a77d",
                    "meaningful_name": "/scratch/zoo/2025/08/14/d949c0203fff19b3216486820e81a77d",
                    "names": [
                        "/scratch/zoo/2025/08/14/d949c0203fff19b3216486820e81a77d"
                    ],
                    "positives": 58,
                    "tags": ["peexe", "spreader", "overlay"],
                    "times_submitted": 1,
                    "type_tags": ["pe", "executable", "win32", "windows", "peexe"],
                    "vhash": "05403d1d1e7az131afz23z2fz",
                },
                "relationships": {},
            }
        },
    ]
}

SCAN_PRIVATE_FILE_UPLOAD_RESPONSE = {
    "data": {
        "type": "private_analysis",
        "id": "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
        "links": {
            "self": "https://www.virustotal.com/api/v3/private/analyses/MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw=="
        },
    }
}

SCAN_PRIVATE_FILE_ANALYSIS_IN_PROGRESS_RESPONSE = {
    "data": {
        "id": "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
        "type": "private_analysis",
        "links": {
            "self": "https://www.virustotal.com/api/v3/private/analyses/MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
            "item": "https://www.virustotal.com/api/v3/private/files/f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
        },
        "attributes": {
            "sandbox_status": {
                "Zenbox": {"in_progress_percent": 29, "status": "running"},
                "CAPE Sandbox": {"in_progress_percent": 25, "status": "running"},
                "OS X Sandbox": {"in_progress_percent": 30, "status": "running"},
            },
            "sandbox_configuration": {
                "internet": 0,
                "command_line": "",
                "intercept_tls": False,
                "locale": 0,
                "live_interaction_analysis_timeout_seconds": 0,
                "live_interaction_sandbox": 0,
            },
            "date": 1755144657,
            "expiration": 1755231056,
            "status": "in-progress",
            "pending_stages": {
                "Zenbox": "Sandbox analysis from Zenbox (running)",
                "CAPE Sandbox": "Sandbox analysis from CAPE Sandbox (running)",
                "OS X Sandbox": "Sandbox analysis from OS X Sandbox (running)",
                "livehunt-behaviour": "Livehunt - Behaviour",
            },
        },
        "meta": {
            "file_info": {
                "md5": "a095b8d1513a9dd40ab99a0fc1f6285b",
                "sha1": "f20aceb9bbe05c8f8c50369bc689385c3d616d73",
                "sha256": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
                "size": 206,
            }
        },
    }
}

SCAN_PRIVATE_FILE_ANALYSIS_COMPLETED_RESPONSE = {
    "data": {
        "id": "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
        "type": "private_analysis",
        "links": {
            "self": "https://www.virustotal.com/api/v3/private/analyses/MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
            "item": "https://www.virustotal.com/api/v3/private/files/f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
        },
        "attributes": {"status": "completed"},
        "meta": {
            "file_info": {
                "sha256": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d"
            }
        },
    }
}

SCAN_PRIVATE_FILE_REPORT_RESPONSE = {
    "data": {
        "id": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
        "type": "private_file",
        "links": {
            "self": "https://www.virustotal.com/api/v3/private/files/f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d"
        },
        "attributes": {
            "ssdeep": "6:rM3dUj1OViMd2hctdQyxXGqdWaT8Wu13Mp:rMNk1fc0ePxWqdWG8v3Mp",
            "magic": "ASCII text, with CRLF line terminators",
            "sha1": "f20aceb9bbe05c8f8c50369bc689385c3d616d73",
            "size": 206,
            "type_extension": "txt",
            "type_tag": "text",
            "magika": "TXT",
            "md5": "a095b8d1513a9dd40ab99a0fc1f6285b",
            "exiftool": {
                "MIMEType": "text/plain",
                "FileType": "TXT",
                "WordCount": "16",
                "LineCount": "16",
                "MIMEEncoding": "us-ascii",
                "FileTypeExtension": "txt",
                "Newlines": "Windows CRLF",
            },
            "available_tools": [],
            "meaningful_name": "github-recovery-codes.txt",
            "crowdsourced_ai_results": [
                {
                    "source": "palm",
                    "id": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
                    "analysis": "The provided data consists of a series of alphanumeric strings, each composed of two hexadecimal segments separated by a hyphen. There is no discernible code logic or functionality within this data. It appears to be a list of identifiers or keys.",
                    "category": "code_insights",
                    "last_modification_date": 1755144657,
                    "creation_date": 1755144657,
                }
            ],
            "tlsh": "T1ECD02317F53767CD17CD2095570C5053093DC1F85D47CB255C37C606506D7339544836",
            "names": ["github-recovery-codes.txt"],
            "type_tags": ["text"],
            "trid": [
                {"file_type": "file seems to be plain text/ASCII", "probability": 0.0}
            ],
            "sha256": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
            "tags": ["text"],
            "type_description": "Text",
            "expiration": 1755231056,
            "last_analysis_date": 1755144657,
            "gti_assessment": {
                "contributing_factors": {"gti_confidence_score": 19},
                "severity": {"value": "SEVERITY_NONE"},
                "threat_score": {"value": 1},
                "verdict": {"value": "VERDICT_UNDETECTED"},
                "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity.",
            },
        },
    }
}

SCAN_PRIVATE_FILE_UPLOAD_URL_RESPONSE = {
    "data": "https://www.virustotal.com/api/v3/private/files/upload"
}

SCAN_PRIVATE_URL_RESPONSE = {
    "data": {
        "type": "private_analysis",
        "id": "ZDk4N2IxMjFhNTBiMDE3OGZhZWFmOTVhZDc3YzE3ODM6OTMzNzQwNWNhMjFkNzFjNWRiMjZiOTk4MmFlYTAxNzA3Yzk1YTkyNWM4ZWY5OWY1YTQyZTdkZDI5ZGMwNmYzZDoxNzU1MTUwNzU1",
        "links": {
            "self": "https://www.virustotal.com/api/v3/private/analyses/ZDk4N2IxMjFhNTBiMDE3OGZhZWFmOTVhZDc3YzE3ODM6OTMzNzQwNWNhMjFkNzFjNWRiMjZiOTk4MmFlYTAxNzA3Yzk1YTkyNWM4ZWY5OWY1YTQyZTdkZDI5ZGMwNmYzZDoxNzU1MTUwNzU1"
        },
    }
}

SCAN_PRIVATE_URL_ANALYSIS_RESPONSE = {
    "data": {
        "id": "ZDk4N2IxMjFhNTBiMDE3OGZhZWFmOTVhZDc3YzE3ODM6OTMzNzQwNWNhMjFkNzFjNWRiMjZiOTk4MmFlYTAxNzA3Yzk1YTkyNWM4ZWY5OWY1YTQyZTdkZDI5ZGMwNmYzZDoxNzU1MTUwNzU1",
        "type": "private_analysis",
        "links": {
            "self": "https://www.virustotal.com/api/v3/private/analyses/ZDk4N2IxMjFhNTBiMDE3OGZhZWFmOTVhZDc3YzE3ODM6OTMzNzQwNWNhMjFkNzFjNWRiMjZiOTk4MmFlYTAxNzA3Yzk1YTkyNWM4ZWY5OWY1YTQyZTdkZDI5ZGMwNmYzZDoxNzU1MTUwNzU1",
            "item": "https://www.virustotal.com/api/v3/private/urls/9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d",
        },
        "attributes": {
            "expiration": 1755237155,
            "status": "completed",
            "sandbox_configuration": {"sandboxes": [20]},
            "date": 1755150755,
        },
    },
    "meta": {
        "url_info": {
            "id": "9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d",
            "url": "https://www.irctc.co.in/",
        }
    },
}

SCAN_PRIVATE_URL_REPORT_RESPONSE = {
    "data": {
        "id": "9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d",
        "type": "private_url",
        "links": {
            "self": "https://www.virustotal.com/api/v3/private/urls/9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d"
        },
        "attributes": {
            "outgoing_links": [],
            "html_meta": {},
            "url": "https://www.irctc.co.in/",
            "redirection_chain": [],
            "title": "",
            "tags": [],
            "tld": "co.in",
            "expiration": 1755237155,
            "last_final_url": "https://www.irctc.co.in/",
            "gti_assessment": {
                "verdict": {"value": "VERDICT_UNDETECTED"},
                "contributing_factors": {
                    "safebrowsing_verdict": "harmless",
                    "pervasive_indicator": bool(True),
                    "gti_confidence_score": 38,
                    "mandiant_confidence_score": 11,
                },
                "threat_score": {"value": 1},
                "severity": {"value": "SEVERITY_NONE"},
                "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity.",
            },
        },
    }
}

SCAN_PUBLIC_FILE_ANALYSIS_RESPONSE = {
    "data": {
        "id": "YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0ODgwMQ==",
        "type": "analysis",
        "links": {
            "self": "https://www.virustotal.com/api/v3/analyses/YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0ODgwMQ==",
            "item": "https://www.virustotal.com/api/v3/files/f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
        },
        "attributes": {
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "harmless": 0,
                "timeout": 0,
                "confirmed-timeout": 0,
                "failure": 0,
                "type-unsupported": 0,
            },
            "date": 1755148801,
            "status": "queued",
            "results": {},
        },
    },
    "meta": {
        "file_info": {
            "sha256": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
            "md5": "a095b8d1513a9dd40ab99a0fc1f6285b",
            "sha1": "f20aceb9bbe05c8f8c50369bc689385c3d616d73",
            "size": 206,
        }
    },
}

SCAN_PUBLIC_FILE_REPORT_RESPONSE = {
    "data": {
        "id": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
        "type": "file",
        "links": {
            "self": "https://www.virustotal.com/api/v3/files/f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d"
        },
        "attributes": {
            "ssdeep": "6:rM3dUj1OViMd2hctdQyxXGqdWaT8Wu13Mp:rMNk1fc0ePxWqdWG8v3Mp",
            "size": 206,
            "downloadable": bool(False),
            "exiftool": {
                "MIMEType": "text/plain",
                "FileType": "TXT",
                "WordCount": "16",
                "LineCount": "16",
                "MIMEEncoding": "us-ascii",
                "FileTypeExtension": "txt",
                "Newlines": "Windows CRLF",
            },
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 63,
                "harmless": 0,
                "timeout": 0,
                "confirmed-timeout": 0,
                "failure": 0,
                "type-unsupported": 14,
            },
            "last_modification_date": 1755148850,
            "magika": "TXT",
            "last_submission_date": 1755148801,
            "times_submitted": 3,
            "available_tools": [],
            "sha1": "f20aceb9bbe05c8f8c50369bc689385c3d616d73",
            "type_extension": "txt",
            "meaningful_name": "github-recovery-codes.txt",
            "tlsh": "T1ECD02317F53767CD17CD2095570C5053093DC1F85D47CB255C37C606506D7339544836",
            "threat_severity": {
                "version": 5,
                "threat_severity_level": "SEVERITY_NONE",
                "threat_severity_data": {},
                "last_analysis_date": "1754909600",
                "level_description": "No severity score data",
            },
            "reputation": 0,
            "sha256": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
            "unique_sources": 1,
            "last_analysis_date": 1755148801,
            "tags": ["text"],
            "md5": "a095b8d1513a9dd40ab99a0fc1f6285b",
            "type_description": "Text",
            "total_votes": {"harmless": 0, "malicious": 0},
            "type_tag": "text",
            "names": ["github-recovery-codes.txt"],
            "type_tags": ["text"],
            "first_submission_date": 1754909413,
            "filecondis": {
                "dhash": "d494009614d48880",
                "raw_md5": "3ffdc66363bfd10e4c5f37cff0b34251",
            },
            "magic": "ASCII text, with CRLF line terminators",
        },
    }
}

SCAN_PUBLIC_FILE_RESPONSE = {
    "data": {
        "type": "analysis",
        "id": "YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0ODgwMQ==",
        "links": {
            "self": "https://www.virustotal.com/api/v3/analyses/YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0ODgwMQ=="
        },
    }
}

SCAN_PUBLIC_URL_RESPONSE = {
    "data": {
        "type": "analysis",
        "id": "u-9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d-1755151622",
        "links": {
            "self": "https://www.virustotal.com/api/v3/analyses/u-9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d-1755151622"
        },
    }
}

SCAN_PUBLIC_URL_ANALYSIS_RESPONSE = {
    "data": {
        "id": "u-9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d-1755151622",
        "type": "analysis",
        "links": {
            "self": "https://www.virustotal.com/api/v3/analyses/u-9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d-1755151622",
            "item": "https://www.virustotal.com/api/v3/urls/9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d",
        },
        "attributes": {
            "status": "queued",
            "date": 1755151622,
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "harmless": 0,
                "timeout": 0,
            },
            "results": {},
        },
    },
    "meta": {
        "url_info": {
            "id": "9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d",
            "url": "https://www.irctc.co.in/",
        }
    },
}

SCAN_PUBLIC_URL_REPORT_RESPONSE = {
    "data": {
        "id": "9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d",
        "type": "url",
        "links": {
            "self": "https://www.virustotal.com/api/v3/urls/9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d"
        },
        "attributes": {
            "threat_severity": {
                "version": "U3",
                "threat_severity_level": "SEVERITY_NONE",
                "threat_severity_data": {},
                "last_analysis_date": "1755132039",
                "level_description": "No severity score data",
            },
            "has_content": bool(False),
            "last_modification_date": 1755151651,
            "reputation": 1,
            "first_submission_date": 1291820392,
            "tags": [],
            "mandiant_ic_score": 11,
            "last_seen_itw_date": 1719244682,
            "total_votes": {"harmless": 1, "malicious": 0},
            "first_seen_itw_date": 1682090919,
            "url": "https://www.irctc.co.in/",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 30,
                "harmless": 67,
                "timeout": 0,
            },
            "title": "",
            "last_final_url": "https://www.irctc.co.in/",
            "tld": "co.in",
            "last_submission_date": 1755151622,
            "times_submitted": 2126,
            "last_analysis_date": 1755151622,
            "categories": {
                "BitDefender": "travel",
                "Sophos": "travel",
                "Forcepoint ThreatSeeker": "travel",
                "Xcitium Verdict Cloud": "government & legal",
            },
            "threat_names": [],
        },
    }
}

VULNERABILITY_API_RESPONSE = {
    "data": [
        {
            "id": "vulnerability--cve-2018-20901",
            "type": "collection",
            "links": {
                "self": "https://www.virustotal.com/api/v3/collections/vulnerability--cve-2018-20901"
            },
            "attributes": {
                "private": True,
                "source_regions_hierarchy": [],
                "autogenerated_tags": [],
                "exploitation_state": "",
                "mitigations": [],
                "epss": {"score": 0.00359, "percentile": 0.57333},
                "vendor_fix_references": [],
                "affected_systems": [],
                "targeted_regions_hierarchy": [],
                "technologies": [],
                "operating_systems": [],
                "detection_names": [],
                "tags_details": [],
                "name": "CVE-2018-20901",
                "available_mitigation": [],
                "priority": "P4",
                "tags": [],
                "description": "cPanel before 71.9980.37 allows Remote-Stored XSS in WHM Save Theme Interface (SEC-400).",
                "status": "COMPUTED",
                "vulnerable_products": "",
                "alt_names_details": [],
                "first_seen_details": [],
                "merged_actors": [],
                "urls_count": 0,
                "threat_scape": [],
                "origin": "Google Threat Intelligence",
                "capabilities": [],
                "targeted_informations": [],
                "motivations": [],
                "files_count": 0,
                "cve_id": "CVE-2018-20901",
                "ip_addresses_count": 0,
                "creation_date": 1675805924,
                "domains_count": 0,
                "targeted_industries_tree": [],
                "last_seen_details": [],
                "executive_summary": "* An Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability exists that, when exploited, allows a remote attacker to achieve unknown impacts.\n* We are currently unaware of exploitation activity in the wild. Exploit code is not publicly available.\n* Google Threat Intelligence Group (GTIG) considers this a Low-risk vulnerability due to unknown impacts, offset by user interaction requirements.\n* There are currently no mitigation options available for this issue.",
                "date_of_disclosure": 1564617600,
                "risk_rating": "",
                "intended_effects": [],
                "predicted_risk_rating": "LOW",
                "malware_roles": [],
                "is_content_translated": False,
                "cwe": {
                    "title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                    "id": "CWE-79",
                },
                "exploitation_consequence": "",
                "collection_links": [],
                "cvss": {
                    "cvssv2_0": {
                        "base_score": 4.3,
                        "vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
                        "temporal_score": 4.3,
                    },
                    "cvssv3_x": {
                        "base_score": 6.1,
                        "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:U/RL:U/RC:C",
                        "temporal_score": 5.6,
                    },
                },
                "alt_names": [],
                "subscribers_count": 0,
                "analysis": "",
                "workarounds": [],
                "top_icon_md5": [],
                "last_modification_date": 1755097862,
                "days_to_report": 1286,
                "mve_id": "MVE-2018-12072",
                "targeted_industries": [],
                "references_count": 0,
                "exploit_availability": "No Known",
                "aggregations": {},
            },
        },
        {
            "id": "vulnerability--cve-2018-20582",
            "type": "collection",
            "links": {
                "self": "https://www.virustotal.com/api/v3/collections/vulnerability--cve-2018-20582"
            },
            "attributes": {
                "mitigations": [],
                "epss": {"score": 0.00145, "percentile": 0.3556},
                "vendor_fix_references": [],
                "affected_systems": [],
                "targeted_regions_hierarchy": [],
                "technologies": [],
                "operating_systems": [],
                "detection_names": [],
                "tags_details": [],
                "name": "CVE-2018-20582",
                "available_mitigation": [],
                "priority": "P3",
                "tags": [],
                "description": "The GREE+ (aka com.gree.greeplus) application 1.4.0.8 for Android suffers from Cross Site Request Forgery.",
                "status": "COMPUTED",
                "vulnerable_products": "",
                "alt_names_details": [],
                "first_seen_details": [],
                "merged_actors": [],
                "urls_count": 0,
                "threat_scape": [],
                "origin": "Google Threat Intelligence",
                "capabilities": [],
                "targeted_informations": [],
                "motivations": [],
                "files_count": 0,
                "cve_id": "CVE-2018-20582",
                "ip_addresses_count": 0,
                "creation_date": 1675805233,
                "domains_count": 0,
                "targeted_industries_tree": [],
                "last_seen_details": [],
                "executive_summary": "* A Cross-Site Request Forgery (CSRF) vulnerability exists that, when exploited, allows an attacker to achieve unknown impacts.\n* We are currently unaware of exploitation activity in the wild. Exploit code is not publicly available.\n* Google Threat Intelligence Group (GTIG) considers this a Medium-risk vulnerability due to unknown impacts, offset by user interaction requirements.\n* There are currently no mitigation options available for this issue.",
                "date_of_disclosure": 1570752000,
                "risk_rating": "",
                "intended_effects": [],
                "predicted_risk_rating": "MEDIUM",
                "cpes": [
                    {
                        "end_cpe": None,
                        "start_rel": "=",
                        "start_cpe": {
                            "version": "1.4.0.8 for Android",
                            "uri": "cpe:2.3:a:gree:gree\\+:1.4.0.8:*:*:*:*:android:*:*",
                            "product": "Gree+",
                            "vendor": "Gree",
                        },
                        "end_rel": None,
                    }
                ],
                "malware_roles": [],
                "is_content_translated": False,
                "cwe": {"title": "Cross-Site Request Forgery (CSRF)", "id": "CWE-352"},
                "exploitation_consequence": "",
                "collection_links": [],
                "cvss": {
                    "cvssv2_0": {
                        "base_score": 6.8,
                        "vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                        "temporal_score": 6.8,
                    },
                    "cvssv3_x": {
                        "base_score": 8.8,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:U/RC:C",
                        "temporal_score": 8.1,
                    },
                },
                "alt_names": [],
                "exploitation_vectors": [],
                "subscribers_count": 0,
                "analysis": "",
                "workarounds": [],
                "top_icon_md5": [],
                "last_modification_date": 1755097860,
                "days_to_report": 1215,
                "mve_id": "MVE-2018-10461",
                "targeted_industries": [],
                "references_count": 0,
                "exploit_availability": "No Known",
                "aggregations": {},
            },
        },
    ]
}

GTI_WIDGET_API_RESPONSE = {
    "data": {
        "id": "1.1.1.1",
        "url": "https://www.virustotal.com/ui/widget/html/MS4xLjEuMXx8aXBfYWRkcmVzc3x8eyJiZDEiOiAiIzRkNjM4NSIsICJiZzEiOiAiIzMxM2Q1YSIsICJiZzIiOiAiIzIyMmM0MiIsICJmZzEiOiAiI2ZmZmZmZiIsICJ0eXBlIjogImRlZmF1bHQifXx8ZnVsbHx8Zm91bmR8fHYzfHwxNzU1MDk3MzI4fHw2YWJhMTQxYjYyYWI5MmM3YmUxNjIzZTdhYjE2NzhjNDA1MTlhOTY0MTI5N2U2ZjA3NmU2MzI2MTFmYTM5Mjdk",
        "detection_ratio": {"detections": 0, "total": 94},
        "type": "ip_address",
        "found": True,
    }
}

DOMAIN = "example.com"

ENRICH_DOMAIN_RELATIONSHIP_API_RESPONSE = {
    "data": {
        "id": DOMAIN,
        "type": "domain",
        "links": {"self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}"},
        "attributes": {
            "popularity_ranks": {
                "Majestic": {"rank": 146, "timestamp": 1755009490},
                "Statvoo": {"timestamp": 1684169881, "rank": 12875},
                "Alexa": {"timestamp": 1684083481, "rank": 12875},
                "Cisco Umbrella": {"rank": 7288, "timestamp": 1755009481},
                "Cloudflare Radar": {"rank": 200, "timestamp": 1755009483},
            },
            "threat_severity": {
                "version": "D3",
                "threat_severity_level": "SEVERITY_NONE",
                "threat_severity_data": {
                    "has_bad_communicating_files_high": True,
                    "has_bad_communicating_files_medium": True,
                    "belongs_to_bad_collection": True,
                    "domain_rank": "8864",
                },
                "last_analysis_date": "1754077171",
                "level_description": "Severity NONE because it has no detections.",
            },
            "reputation": 8,
            "tld": "com",
            "registrar": "RESERVED-Internet Assigned Numbers Authority",
            "last_dns_records": [
                {"type": "AAAA", "ttl": 211, "value": "2600:1408:ec00:36::1736:7f31"},
                {"type": "A", "ttl": 224, "value": "96.7.128.175"},
                {
                    "type": "TXT",
                    "ttl": 5846,
                    "value": "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9",
                },
                {"type": "TXT", "ttl": 5846, "value": "v=spf1 -all"},
                {"type": "A", "ttl": 224, "value": "23.192.228.84"},
                {"type": "AAAA", "ttl": 211, "value": "2600:1406:bc00:53::b81e:94c8"},
                {
                    "type": "SOA",
                    "ttl": 595,
                    "value": "ns.icann.org",
                    "rname": "noc.dns.icann.org",
                    "serial": 2025011746,
                    "refresh": 7200,
                    "retry": 3600,
                    "expire": 1209600,
                    "minimum": 3600,
                },
                {"type": "A", "ttl": 224, "value": "23.192.228.80"},
                {"type": "AAAA", "ttl": 211, "value": "2600:1406:3a00:21::173e:2e66"},
                {"type": "AAAA", "ttl": 211, "value": "2600:1406:3a00:21::173e:2e65"},
                {"type": "NS", "ttl": 4777, "value": "a.iana-servers.net"},
                {"type": "A", "ttl": 224, "value": "23.215.0.138"},
                {"type": "MX", "ttl": 16047, "priority": 0, "value": ""},
                {"type": "A", "ttl": 224, "value": "23.215.0.136"},
                {"type": "AAAA", "ttl": 211, "value": "2600:1406:bc00:53::b81e:94ce"},
                {"type": "A", "ttl": 224, "value": "96.7.128.198"},
                {"type": "AAAA", "ttl": 211, "value": "2600:1408:ec00:36::1736:7f24"},
                {"type": "NS", "ttl": 4777, "value": "b.iana-servers.net"},
            ],
            "first_seen_itw_date": 1530174464,
            "whois": "Creation Date: 1995-08-14T04:00:00Z\nDNSSEC: signedDelegation\nDomain Name: EXAMPLE.COM\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nName Server: A.IANA-SERVERS.NET\nName Server: B.IANA-SERVERS.NET\nRegistrar IANA ID: 376\nRegistrar URL: http://res-dom.iana.org\nRegistrar WHOIS Server: whois.iana.org\nRegistrar: RESERVED-Internet Assigned Numbers Authority\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2025-08-13T04:00:00Z\nUpdated Date: 2024-08-14T07:01:34Z\ncreated: 1992-01-01\ndomain: EXAMPLE.COM\norganisation: Internet Assigned Numbers Authority\nsource: IANA",
            "last_update_date": 1723618894,
            "last_analysis_results": {
                "Acronis": {
                    "method": "blacklist",
                    "engine_name": "Acronis",
                    "category": "harmless",
                    "result": "clean",
                },
                "0xSI_f33d": {
                    "method": "blacklist",
                    "engine_name": "0xSI_f33d",
                    "category": "undetected",
                    "result": "unrated",
                },
                # ... (other analysis results omitted for brevity)
            },
            "mandiant_ic_score": 0,
            "last_seen_itw_date": 1753273339,
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 29,
                "harmless": 65,
                "timeout": 0,
            },
            "last_modification_date": 1755088735,
            "last_https_certificate": {
                "cert_signature": {
                    "signature_algorithm": "1.2.840.10045.4.3.3",
                    "signature": "3065023100f9a6824653db6fe558faee1abcfc9a1bb7ef50326a37c2b096b5c3e17a6d4fb40bf83d37f8103f154128ddd0f58b3dfb0230646378e1b2e2c05bba56b036ed5ff430c69ea436c2b88e1d7f463bd5ff6eb4b3143033f18ceedd3e4f4b8fd8bf98d765",
                },
                "extensions": {
                    "authority_key_identifier": {
                        "keyid": "8a23eb9e6bd7f9375df96d2139769aa167de10a8"
                    },
                    "subject_key_identifier": "f0c16a320decdac7ea8fcd0d6d191259d1be72ed",
                    "subject_alternative_name": ["*.example.com", "example.com"],
                    "certificate_policies": ["2.23.140.1.2.2"],
                    "key_usage": ["digitalSignature", "keyAgreement"],
                    "extended_key_usage": ["serverAuth", "clientAuth"],
                    "crl_distribution_points": [
                        "http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
                        "http://crl4.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl",
                    ],
                },
            },
            "last_analysis_date": 1755081367,
            "last_dns_records_date": 1755081395,
            "last_https_certificate_date": 1755081395,
            "whois_date": 1754249959,
            "creation_date": 808372800,
            "gti_assessment": {
                "threat_score": {"value": 0},
                "contributing_factors": {
                    "mandiant_analyst_benign": True,
                    "malicious_sandbox_verdict": False,
                    "mandiant_confidence_score": 0,
                    "pervasive_indicator": True,
                    "google_mobile_malware_analysis": True,
                    "gti_confidence_score": 0,
                    "associated_malware_configuration": True,
                    "google_malware_analysis": True,
                },
                "severity": {"value": "SEVERITY_NONE"},
                "verdict": {"value": "VERDICT_BENIGN"},
                "description": "This indicator was determined as benign by a Mandiant analyst and likely poses no threat.",
            },
        },
        "relationships": {
            "related_threat_actors": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/related_threat_actors?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/related_threat_actors",
                },
            },
            "software_toolkits": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/software_toolkits?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/software_toolkits",
                },
            },
            "comments": {
                "data": [
                    {"type": "comment", "id": f"d-{DOMAIN}-53c4ee48"},
                    {"type": "comment", "id": f"d-{DOMAIN}-b3367d20"},
                    # ... (other comments omitted for brevity)
                ],
                "meta": {
                    "cursor": "CmYKEQoEZGF0ZRIJCIeT08aa3P0CEk1qEXN-dmlydXN0b3RhbGNsb3VkcjgLEgZEb21haW4iC2V4YW1wbGUuY29tDAsSB0NvbW1lbnQiFGV4YW1wbGUuY29tLTE3ZTVlZWZiDBgAIAE="
                },
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/comments?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/comments",
                    "next": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/comments?limit=20&cursor=CmYKEQoEZGF0ZRIJCIeT08aa3P0CEk1qEXN-dmlydXN0b3RhbGNsb3VkcjgLEgZEb21haW4iC2V4YW1wbGUuY29tDAsSB0NvbW1lbnQiFGV4YW1wbGUuY29tLTE3ZTVlZWZiDBgAIAE%3D",
                },
            },
            "reports": {
                "data": [
                    {
                        "type": "collection",
                        "id": "report--07c21ff12371d72802763a1ce5336f8d5ba0b7e3d8b26bb42fb6bce01737700e",
                    },
                    {
                        "type": "collection",
                        "id": "report--0b2f7f0b7a284a075186a865e3665e6636cd0060d370d0ec8e6e9a6e01c7941c",
                    },
                    # ... (other reports omitted for brevity)
                ],
                "meta": {"cursor": "eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9"},
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/reports?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/reports",
                    "next": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/reports?limit=20&cursor=eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9",
                },
            },
            "campaigns": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/campaigns?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/campaigns",
                },
            },
            "vulnerabilities": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/vulnerabilities?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/vulnerabilities",
                },
            },
            "resolutions": {
                "data": [
                    {"type": "resolution", "id": f"23.192.228.80{DOMAIN}"},
                    {"type": "resolution", "id": f"23.192.228.84{DOMAIN}"},
                    # ... (other resolutions omitted for brevity)
                ],
                "meta": {
                    "cursor": f"ClYKEQoEZGF0ZRIJCIDeq5zp6usCEj1qEXN-dmlydXN0b3RhbGNsb3VkcigLEgpSZXNvbHV0aW9uIhg5My4xODQuMjE2LjM0ZXhhbXBsZS5jb20MGAAgAQ=="
                },
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/resolutions?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/resolutions",
                    "next": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/resolutions?limit=20&cursor=ClYKEQoEZGF0ZRIJCIDeq5zp6usCEj1qEXN-dmlydXN0b3RhbGNsb3VkcigLEgpSZXNvbHV0aW9uIhg5My4xODQuMjE2LjM0ZXhhbXBsZS5jb20MGAAgAQ%3D%3D",
                },
            },
            "malware_families": {
                "data": [
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_zenbox_metasploit",
                    },
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_zenbox_quasarrat",
                    },
                ],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/malware_families?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/malware_families",
                },
            },
            "collections": {
                "data": [
                    {
                        "type": "collection",
                        "id": "01a0b648d01ba35039bc6227679b3bdc67f3300964056f1c289c8d78d4576f6d",
                    },
                    {
                        "type": "collection",
                        "id": "03c85ae73aba9297a14cdd6a12f37ac20a68c709d84e1cb81e3f91804c63879f",
                    },
                    # ... (other collections omitted for brevity)
                ],
                "meta": {"cursor": "eyJsaW1pdCI6IDIwLCAib2Zfc2V0IjogMjB9"},
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/collections?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/collections",
                    "next": f"https://www.virustotal.com/api/v3/domains/{DOMAIN}/relationships/collections?limit=20&cursor=eyJsaW1pdCI6IDIwLCAib2Zfc2V0IjogMjB9",
                },
            },
        },
    }
}

ENRICH_DOMAIN_API_RESPONSE = {
    "data": {
        "id": DOMAIN,
        "type": "domain",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "harmless": 65,
                "undetected": 29,
                "suspicious": 0,
                "timeout": 0,
            },
            "gti_assessment": {
                "verdict": {"value": "VERDICT_BENIGN"},
                "threat_score": {"value": 0},
                "severity": {"value": "SEVERITY_NONE"},
                "contributing_factors": {
                    "malicious_sandbox_verdict": False,
                    "mandiant_analyst_benign": True,
                },
                "description": "This indicator was determined as benign.",
            },
        },
    }
}

FILE_HASH = "0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2"

ENRICH_FILE_API_RESPONSE = {
    "data": {
        "id": FILE_HASH,
        "type": "file",
        "links": {"self": f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"},
        "attributes": {
            "unique_sources": 1,
            "sha256": FILE_HASH,
            "times_submitted": 1,
            "last_modification_date": 1747713784,
            "authentihash": "51f0e2231c12ba010e1fedc0cf77fe02bc5f61e0ec66b52bdc410194f9eafdf2",
            "sha1": "33d915448f1bc6b8a479d160a73df38129a4ccb1",
            "available_tools": ["capa"],
            "magic": "PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows",
            "last_analysis_date": 1747109144,
            "type_description": "Win32 EXE",
            "total_votes": {"harmless": 0, "malicious": 0},
            "md5": "37ece581c10a7a88ee6c666b13807a03",
            "type_tag": "peexe",
            "type_extension": "exe",
            "ssdeep": "49152:ieutLO9rb/TrvO90dL3BmAFd4A64nsfJJ2TIA5GNP1Jr4u/TgAPNdi9128qk1q4o:ieF+iIAEl1JPz212IhzL+Bzz3dw/Vkz",
            "size": 4385462,
            "sandbox_verdicts": {
                "C2AE": {
                    "category": "undetected",
                    "malware_classification": ["UNKNOWN_VERDICT"],
                    "sandbox_name": "C2AE",
                }
            },
            "last_analysis_stats": {
                "malicious": 44,
                "suspicious": 0,
                "undetected": 29,
                "harmless": 0,
                "timeout": 0,
                "confirmed-timeout": 0,
                "failure": 0,
                "type-unsupported": 4,
            },
            "first_submission_date": 1747109144,
            "reputation": 0,
            "vhash": "0460d6655d55557575157az28!z",
            "tlsh": "T156169D03FC9564A9C5E9F23089758392BA717858473127D33F64AABB2A737C41FB9390",
            "gti_assessment": {
                "threat_score": {"value": 80},
                "verdict": {"value": "VERDICT_MALICIOUS"},
                "severity": {"value": "SEVERITY_HIGH"},
                "contributing_factors": {
                    "gavs_detections": 3,
                    "gavs_categories": ["ransom"],
                    "normalised_categories": ["ransomware"],
                },
                "description": "This indicator is malicious (high severity) with high impact. It was detected by Google's spam and threat filtering engines, categorised as ransomware and categorised as ransomware. Analysts should prioritize investigation.",
            },
        },
    }
}

RELATIONSHIP_FILE_HASH = (
    "001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0"
)

ENRICH_FILE_RELATIONSHIPS_RESPONSE = {
    "data": {
        "id": RELATIONSHIP_FILE_HASH,
        "type": "file",
        "links": {
            "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}"
        },
        "attributes": {
            "sha256": RELATIONSHIP_FILE_HASH,
            "type_tags": ["executable", "windows", "win32", "pe", "peexe"],
            "sha1": "33d915448f1bc6b8a479d160a73df38129a4ccb1",
            "type_extension": "exe",
            "reputation": 0,
            "md5": "37ece581c10a7a88ee6c666b13807a03",
            "tags": ["peexe", "64bits", "overlay", "spreader"],
            "last_analysis_date": 1747109144,
            "ssdeep": "49152:ieutLO9rb/TrvO90dL3BmAFd4A64nsfJJ2TIA5GNP1Jr4u/TgAPNdi9128qk1q4o:ieF+iIAEl1JPz212IhzL+Bzz3dw/Vkz",
            "type_description": "Win32 EXE",
            "sandbox_verdicts": {
                "C2AE": {
                    "category": "undetected",
                    "malware_classification": ["UNKNOWN_VERDICT"],
                    "sandbox_name": "C2AE",
                }
            },
            "total_votes": {"harmless": 0, "malicious": 0},
            "names": ["/scratch/zoo/2025/05/13/37ece581c10a7a88ee6c666b13807a03"],
            "tlsh": "T156169D03FC9564A9C5E9F23089758392BA717858473127D33F64AABB2A737C41FB9390",
            "vhash": "0460d6655d55557575157az28!z",
            "unique_sources": 1,
            "filecondis": {
                "dhash": "587c3e1c0e260b00",
                "raw_md5": "316cea3edc759c94fe20b6b2b88ce9dc",
            },
            "downloadable": True,
            "authentihash": "51f0e2231c12ba010e1fedc0cf77fe02bc5f61e0ec66b52bdc410194f9eafdf2",
            "last_modification_date": 1747713784,
            "last_analysis_stats": {
                "malicious": 44,
                "suspicious": 0,
                "undetected": 29,
                "harmless": 0,
                "timeout": 0,
                "confirmed-timeout": 0,
                "failure": 0,
                "type-unsupported": 4,
            },
            "last_submission_date": 1747109144,
            "type_tag": "peexe",
            "times_submitted": 1,
            "available_tools": ["capa"],
            "magic": "PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows",
            "first_submission_date": 1747109144,
            "size": 4385462,
            "gti_assessment": {
                "contributing_factors": {
                    "gavs_detections": 3,
                    "normalised_categories": ["ransomware"],
                    "gavs_categories": ["ransom"],
                },
                "threat_score": {"value": 80},
                "verdict": {"value": "VERDICT_MALICIOUS"},
                "severity": {"value": "SEVERITY_HIGH"},
                "description": "This indicator is malicious (high severity) with high impact. It was detected by Google's spam and threat filtering engines, categorised as ransomware and categorised as ransomware. Analysts should prioritize investigation.",
            },
        },
        "relationships": {
            "malware_families": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/malware_families?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/malware_families",
                },
            },
            "campaigns": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/campaigns?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/campaigns",
                },
            },
            "vulnerabilities": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/vulnerabilities?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/vulnerabilities",
                },
            },
            "collections": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/collections?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/collections",
                },
            },
            "reports": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/reports?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/reports",
                },
            },
            "comments": {
                "data": [
                    {"type": "comment", "id": f"f-{RELATIONSHIP_FILE_HASH}-0834142e"},
                    {"type": "comment", "id": f"f-{RELATIONSHIP_FILE_HASH}-85e09b06"},
                    {"type": "comment", "id": f"f-{RELATIONSHIP_FILE_HASH}-9e9de98c"},
                ],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/comments?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/comments",
                },
            },
            "software_toolkits": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/software_toolkits?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/software_toolkits",
                },
            },
            "related_threat_actors": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/relationships/related_threat_actors?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/files/{RELATIONSHIP_FILE_HASH}/related_threat_actors",
                },
            },
        },
    }
}

ENRICH_FILE_MITRE_RESPONSE = {
    "data": {
        "C2AE": {
            "tactics": [
                {
                    "name": "Persistence",
                    "id": "TA0003",
                    "techniques": [
                        {
                            "name": "Registry Run Keys / Startup Folder",
                            "id": "T1547.001",
                        },
                        {"name": "Scheduled Task/Job", "id": "T1053"},
                    ],
                },
                {
                    "name": "Defense Evasion",
                    "id": "TA0005",
                    "techniques": [
                        {"name": "Obfuscated Files or Information", "id": "T1027"}
                    ],
                },
            ]
        }
    }
}

ENRICH_FILE_SANDBOX_RESPONSE = {
    "data": [
        {
            "attributes": {
                "sandbox_name": "C2AE",
                "id": "beh-001",
                "command_executions": [
                    "cmd.exe /c echo malicious > file.txt",
                    "net user add malicious_user",
                ],
            }
        },
        {
            "attributes": {
                "sandbox_name": "Zenbox",
                "id": "beh-002",
                "command_executions": ["powershell.exe -exec bypass"],
            }
        },
    ]
}

IP_ADDRESS = "8.8.8.8"

ENRICH_IP_RELATIONSHIP_API_RESPONSE = {
    "data": {
        "id": IP_ADDRESS,
        "type": "ip_address",
        "links": {
            "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}"
        },
        "attributes": {
            "first_seen_itw_date": 1409607591,
            "as_owner": "GOOGLE",
            "reputation": 556,
            "last_analysis_date": 1755064038,
            "country": "US",
            "asn": 15169,
            "regional_internet_registry": "ARIN",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 32,
                "harmless": 62,
                "timeout": 0,
            },
            "whois_date": 1754827902,
            "network": "8.8.8.0/24",
            "last_seen_itw_date": 1755044120,
            "threat_severity": {
                "version": "I3",
                "threat_severity_level": "SEVERITY_NONE",
                "threat_severity_data": {
                    "has_bad_communicating_files_high": True,
                    "has_bad_communicating_files_medium": True,
                    "belongs_to_bad_collection": True,
                },
                "last_analysis_date": "1755044938",
                "level_description": "Severity NONE because it has no detections.",
            },
            "tags": [],
            "last_https_certificate_date": 1755064050,
            "mandiant_ic_score": 0,
            "whois": "NetRange: 8.8.8.0 - 8.8.8.255\nCIDR: 8.8.8.0/24\nNetName: GOGL\nNetHandle: NET-8-8-8-0-2\nParent: NET8 (NET-8-0-0-0-0)\nNetType: Direct Allocation\nOriginAS: \nOrganization: Google LLC (GOGL)\nRegDate: 2023-12-28\nUpdated: 2023-12-28\nRef: https://rdap.arin.net/registry/ip/8.8.8.0\nOrgName: Google LLC\nOrgId: GOGL\nAddress: 1600 Amphitheatre Parkway\nCity: Mountain View\nStateProv: CA\nPostalCode: 94043\nCountry: US\nRegDate: 2000-03-30\nUpdated: 2019-10-31\nComment: Please note that the recommended way to file abuse complaints are located in the following links. \nComment: \nComment: To report abuse and illegal activity: https://www.google.com/contact/\nComment: \nComment: For legal requests: http://support.google.com/legal \nComment: \nComment: Regards, \nComment: The Google Team\nRef: https://rdap.arin.net/registry/entity/GOGL\nOrgTechHandle: ZG39-ARIN\nOrgTechName: Google LLC\nOrgTechPhone: +1-650-253-0000 \nOrgTechEmail: arin-contact@google.com\nOrgTechRef: https://rdap.arin.net/registry/entity/ZG39-ARIN\nOrgAbuseHandle: ABUSE5250-ARIN\nOrgAbuseName: Abuse\nOrgAbusePhone: +1-650-253-0000 \nOrgAbuseEmail: network-abuse@google.com\nOrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE5250-ARIN\n",
            "total_votes": {"harmless": 236, "malicious": 44},
            "jarm": "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
            "continent": "NA",
            "last_modification_date": 1755089627,
            "gti_assessment": {
                "contributing_factors": {
                    "normalised_categories": [
                        "phishing",
                        "malware",
                        "phishing",
                        "infostealer",
                        "malware",
                        "control-server",
                    ],
                    "mandiant_association_report": True,
                    "gti_confidence_score": 0,
                    "mandiant_confidence_score": 0,
                    "pervasive_indicator": True,
                    "mandiant_analyst_benign": True,
                    "malicious_sandbox_verdict": False,
                    "google_malware_analysis": True,
                },
                "verdict": {"value": "VERDICT_BENIGN"},
                "severity": {"value": "SEVERITY_NONE"},
                "threat_score": {"value": 0},
                "description": "This indicator was determined as benign by a Mandiant analyst and likely poses no threat.",
            },
        },
        "relationships": {
            "related_threat_actors": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/related_threat_actors?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/related_threat_actors",
                },
            },
            "reports": {
                "data": [
                    {"type": "collection", "id": "report--19-00000879"},
                    {"type": "collection", "id": "report--19-00007287"},
                    {"type": "collection", "id": "report--21-00005331"},
                    {"type": "collection", "id": "report--21-00006507"},
                    {
                        "type": "collection",
                        "id": "report--21-00006806",
                        "context_attributes": {
                            "related_from": [
                                {
                                    "type": "collection",
                                    "id": "report--21-00006507",
                                    "attributes": {
                                        "name": "ICS Network Activity Report: March 15–21, 2021",
                                        "tags": [],
                                        "origin": "Google Threat Intelligence",
                                        "collection_type": "report",
                                    },
                                }
                            ]
                        },
                    },
                    {
                        "type": "collection",
                        "id": "report--21-00008593",
                        "context_attributes": {
                            "related_from": [
                                {
                                    "type": "collection",
                                    "id": "report--21-00008611",
                                    "attributes": {
                                        "name": "ICS Network Activity Report: April 12–18, 2021",
                                        "tags": [],
                                        "origin": "Google Threat Intelligence",
                                        "collection_type": "report",
                                    },
                                }
                            ]
                        },
                    },
                    {"type": "collection", "id": "report--21-00008611"},
                    {"type": "collection", "id": "report--21-00009361"},
                    {"type": "collection", "id": "report--21-00009891"},
                    {"type": "collection", "id": "report--21-00011570"},
                    {"type": "collection", "id": "report--21-00013561"},
                    {"type": "collection", "id": "report--21-00014853"},
                    {"type": "collection", "id": "report--21-00015655"},
                    {"type": "collection", "id": "report--21-00018662"},
                    {"type": "collection", "id": "report--21-00021155"},
                    {"type": "collection", "id": "report--21-00025023"},
                    {"type": "collection", "id": "report--21-00025712"},
                    {"type": "collection", "id": "report--22-00004673"},
                    {
                        "type": "collection",
                        "id": "report--22-00005503",
                        "context_attributes": {
                            "related_from": [
                                {
                                    "type": "collection",
                                    "id": "report--22-00004673",
                                    "attributes": {
                                        "name": "Czech Government Targeted with Russia-Ukraine Conflict Lure from Suspected Chinese Threat Group",
                                        "tags": [],
                                        "origin": "Google Threat Intelligence",
                                        "collection_type": "report",
                                    },
                                }
                            ]
                        },
                    },
                    {
                        "type": "collection",
                        "id": "report--22-00007926",
                        "context_attributes": {
                            "related_from": [
                                {
                                    "type": "collection",
                                    "id": "report--22-00004673",
                                    "attributes": {
                                        "name": "Czech Government Targeted with Russia-Ukraine Conflict Lure from Suspected Chinese Threat Group",
                                        "tags": [],
                                        "origin": "Google Threat Intelligence",
                                        "collection_type": "report",
                                    },
                                }
                            ]
                        },
                    },
                ],
                "meta": {"cursor": "eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9"},
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/reports?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/reports",
                    "next": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/reports?limit=20&cursor=eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9",
                },
            },
            "vulnerabilities": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/vulnerabilities?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/vulnerabilities",
                },
            },
            "resolutions": {
                "data": [
                    {"type": "resolution", "id": f"{IP_ADDRESS}sanam.ie"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}dlufy.lat"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}dogukangazel.com.tr"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}198.qzz.io"},
                    {
                        "type": "resolution",
                        "id": f"{IP_ADDRESS}gtm-cn-2g74cs7dp01.gtm-cw.cn",
                    },
                    {"type": "resolution", "id": f"{IP_ADDRESS}xn--czrv40b45s.com"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}siproin.com.ar"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}risedigital.ma"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}netschool.ma"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}joystickstudios.ma"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}sthry.dpdns.org"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}faithex.ma"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}baidunewsblog.org.cn"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}seonewsblog.org.cn"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}sohunewsblog.cn"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}taobaonewsblog.cn"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}taobaonewsblog.org.cn"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}cnnewsblog.cn"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}sohunewsblog.org.cn"},
                    {"type": "resolution", "id": f"{IP_ADDRESS}cnnewsblog.org.cn"},
                ],
                "meta": {
                    "cursor": f"ClYKEQoEZGF0ZRIJCLad2ryLh48DEj1qEXN-dmlydXN0b3RhbGNsb3VkcigLEgpSZXNvbHV0aW9uIhg4LjguOC44Y25uZXdzYmxvZy5vcmcuY24MGAAgAQ=="
                },
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/resolutions?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/resolutions",
                    "next": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/resolutions?limit=20&cursor=ClYKEQoEZGF0ZRIJCLad2ryLh48DEj1qEXN-dmlydXN0b3RhbGNsb3VkcigLEgpSZXNvbHV0aW9uIhg4LjguOC44Y25uZXdzYmxvZy5vcmcuY24MGAAgAQ%3D%3D",
                },
            },
            "comments": {
                "data": [
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-9a1efa42"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-eee06853"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-5b4ae5c2"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-a80560b3"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-ab69d19c"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-0772d4ca"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-3677dc43"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-285c4c87"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-a5526c3a"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-55e4225d"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-73104253"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-3be8e247"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-b32fade5"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-3f314021"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-c8ccf63b"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-a5d35211"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-5c8dd570"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-f045fee5"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-6093261d"},
                    {"type": "comment", "id": f"i-{IP_ADDRESS}-f423f04f"},
                ],
                "meta": {
                    "cursor": f"CmEKEQoEZGF0ZRIJCJOX0P3s74sDEkhqEXN-dmlydXN0b3RhbGNsb3VkcjMLEglJcEFkZHJlc3MiBzguOC44LjgMCxIHQ29tbWVudCIQOC44LjguOC1mNDIzZjA0ZgwYACAB"
                },
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/comments?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/comments",
                    "next": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/comments?limit=20&cursor=CmEKEQoEZGF0ZRIJCJOX0P3s74sDEkhqEXN-dmlydXN0b3RhbGNsb3VkcjMLEglJcEFkZHJlc3MiBzguOC44LjgMCxIHQ29tbWVudCIQOC44LjguOC1mNDIzZjA0ZgwYACAB",
                },
            },
            "malware_families": {
                "data": [
                    {"type": "collection", "id": "analysis_virustotal_cape_dcrat"},
                    {"type": "collection", "id": "analysis_virustotal_cape_metasploit"},
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_vmray_comments_asyncrat",
                    },
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_vmray_comments_quasarrat",
                    },
                    {"type": "collection", "id": "analysis_virustotal_zenbox_asyncrat"},
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_zenbox_cobaltstrike",
                    },
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_zenbox_metasploit",
                    },
                    {"type": "collection", "id": "analysis_virustotal_zenbox_njrat"},
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_zenbox_quasarrat",
                    },
                    {"type": "collection", "id": "threatfox_elf_mirai"},
                ],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/malware_families?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/malware_families",
                },
            },
            "software_toolkits": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/software_toolkits?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/software_toolkits",
                },
            },
            "collections": {
                "data": [
                    {
                        "type": "collection",
                        "id": "05697f9748019f741e42b8633c240f5442458e57986a654125e93753cfd2e652",
                    },
                    {
                        "type": "collection",
                        "id": "0a42f06eb1ab1612ebc1c6b7b2a85862c0469fdbd065798454a055a9f0c85ef4",
                    },
                    {
                        "type": "collection",
                        "id": "0a7267fd188759ce84ecfc9008167a9cbd457fd14e4a0fccd39aef22e20a2c9c",
                    },
                    {
                        "type": "collection",
                        "id": "0d757f885f9a5a94e382e8a6d0a2371659a5e425422c515b799cb4f86b99a356",
                    },
                    {
                        "type": "collection",
                        "id": "100d2e703331aa1c3ae85898bc5f4623299cfc15b072c2686ae49a3c6cd0bf2c",
                    },
                    {
                        "type": "collection",
                        "id": "11a4d1298538d915e6d7a3bd4c6f045a1ff0e1edc2396924cfd3d33d3cde3d63",
                    },
                    {
                        "type": "collection",
                        "id": "12a423dc39d75e4cedd7aee52d4b7e628f170c9fcccf3c87f31892882df331fa",
                    },
                    {
                        "type": "collection",
                        "id": "16817ea2e2130a9b979cd3123220155717c9c97603c6503cc1e1ca5ff907b018",
                    },
                    {
                        "type": "collection",
                        "id": "1855d5c29b31d76e899745943710a929813a4e4293be7f28eec976ad29128ba5",
                    },
                    {
                        "type": "collection",
                        "id": "1b815a0ecaf97e64988edf7ec602834dd3cb9eb66cbce0f7398538244e3eb601",
                    },
                    {
                        "type": "collection",
                        "id": "1e46bfdfa2c3534a1355ffb9d7e75e01b5e3058f9b89b56deb06fc0ee661b215",
                    },
                    {
                        "type": "collection",
                        "id": "1ed1e66d15fef841076cd493bc3dd3a9e04cc07b2d8fe82357b9fb812423002b",
                    },
                    {
                        "type": "collection",
                        "id": "202c75f5451f2ec049798bc3c2a32fe81560bd1bee959533499cc2e20f47bf47",
                    },
                    {
                        "type": "collection",
                        "id": "2441d3d0736ac4d8b411f5fd8fe7d7645ab688f7b55160b07ccce9baa631b00b",
                    },
                    {
                        "type": "collection",
                        "id": "2b97f0bd6631b3f3d0bf2e9601307f23bd75b9b5103ac50c8b662bb287a6f65a",
                    },
                    {
                        "type": "collection",
                        "id": "38ff14d6322f59feb863b2c88e53bc1e92cb6d815f94f6f6f9fd7e0efd16b88b",
                    },
                    {
                        "type": "collection",
                        "id": "5189278986e304fc8e7a4b25bde7c24fa39daafcbd879d78168c63259b401125",
                    },
                    {
                        "type": "collection",
                        "id": "5210884d2b3252071a08175a485fc294288cbb6abdbd25321c8fd043d85becf4",
                    },
                    {
                        "type": "collection",
                        "id": "5330a90d47f35ad4484980f52152deb7a4167434e851253a30fb5eae8e812c1e",
                    },
                    {
                        "type": "collection",
                        "id": "55a3d64fad84b8bf795029b1d7f73053b0e087541f5e2913c5c4b4487af303b2",
                    },
                ],
                "meta": {"cursor": "eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9"},
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/collections?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/collections",
                    "next": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/collections?limit=20&cursor=eyJsaW1pdCI6IDIwLCAib2Zfc2V0IjogMjB9",
                },
            },
            "campaigns": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/relationships/campaigns?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}/campaigns",
                },
            },
        },
    }
}

ENRICH_IP_API_RESPONSE = {
    "data": {
        "id": IP_ADDRESS,
        "type": "ip_address",
        "links": {
            "self": f"https://www.virustotal.com/api/v3/ip_addresses/{IP_ADDRESS}"
        },
        "attributes": {
            "as_owner": "GOOGLE",
            "network": "8.8.8.0/24",
            "whois": "NetRange: 8.8.8.0 - 8.8.8.255\nCIDR: 8.8.8.0/24\nNetName: GOGL\nNetHandle: NET-8-8-8-0-2\nParent: NET8 (NET-8-0-0-0-0)\nNetType: Direct Allocation\nOriginAS: \nOrganization: Google LLC (GOGL)\nRegDate: 2023-12-28\nUpdated: 2023-12-28\nRef: https://rdap.arin.net/registry/ip/8.8.8.0\nOrgName: Google LLC\nOrgId: GOGL\nAddress: 1600 Amphitheatre Parkway\nCity: Mountain View\nStateProv: CA\nPostalCode: 94043\nCountry: US\nRegDate: 2000-03-30\nUpdated: 2019-10-31\nComment: Please note that the recommended way to file abuse complaints are located in the following links. \nComment: \nComment: To report abuse and illegal activity: https://www.google.com/contact/\nComment: \nComment: For legal requests: http://support.google.com/legal \nComment: \nComment: Regards, \nComment: The Google Team\nRef: https://rdap.arin.net/registry/entity/GOGL\nOrgTechHandle: ZG39-ARIN\nOrgTechName: Google LLC\nOrgTechPhone: +1-650-253-0000 \nOrgTechEmail: arin-contact@google.com\nOrgTechRef: https://rdap.arin.net/registry/entity/ZG39-ARIN\nOrgAbuseHandle: ABUSE5250-ARIN\nOrgAbuseName: Abuse\nOrgAbusePhone: +1-650-253-0000 \nOrgAbuseEmail: network-abuse@google.com\nOrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE5250-ARIN\n",
            "asn": 15169,
            "last_seen_itw_date": 1755044120,
            "whois_date": 1754827902,
            "first_seen_itw_date": 1409607591,
            "threat_severity": {
                "version": "I3",
                "threat_severity_level": "SEVERITY_NONE",
                "threat_severity_data": {
                    "has_bad_communicating_files_high": True,
                    "has_bad_communicating_files_medium": True,
                    "belongs_to_bad_collection": True,
                },
                "last_analysis_date": "1755044938",
                "level_description": "Severity NONE because it has no detections.",
            },
            "last_analysis_date": 1755064038,
            "regional_internet_registry": "ARIN",
            "jarm": "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
            "last_https_certificate_date": 1755064050,
            "mandiant_ic_score": 0,
            "tags": [],
            "total_votes": {"harmless": 236, "malicious": 44},
            "continent": "NA",
            "country": "US",
            "reputation": 556,
            "last_modification_date": 1755089280,
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 32,
                "harmless": 62,
                "timeout": 0,
            },
            "gti_assessment": {
                "threat_score": {"value": 0},
                "verdict": {"value": "VERDICT_BENIGN"},
                "severity": {"value": "SEVERITY_NONE"},
                "contributing_factors": {
                    "pervasive_indicator": True,
                    "normalised_categories": [
                        "phishing",
                        "malware",
                        "phishing",
                        "infostealer",
                        "malware",
                        "control-server",
                    ],
                    "mandiant_analyst_benign": True,
                    "malicious_sandbox_verdict": False,
                    "mandiant_association_report": True,
                    "mandiant_confidence_score": 0,
                    "gti_confidence_score": 0,
                    "google_malware_analysis": True,
                },
                "description": "This indicator was determined as benign by a Mandiant analyst and likely poses no threat.",
            },
        },
    }
}

ENRICH_URL = "https://www.youtube.com"

ENRICH_URL_ID = base64.urlsafe_b64encode(ENRICH_URL.encode()).decode().rstrip("=")

ENRICH_URL_API_RESPONSE = {
    "data": {
        "id": ENRICH_URL_ID,
        "type": "url",
        "links": {"self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}"},
        "attributes": {
            "tld": "com",
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 26,
                "harmless": 71,
                "timeout": 0,
            },
            "gti_assessment": {
                "contributing_factors": {
                    "malicious_sandbox_verdict": False,
                    "safebrowsing_verdict": "harmless",
                    "mandiant_confidence_score": 3,
                    "gti_confidence_score": 8,
                    "pervasive_indicator": True,
                    "associated_malware_configuration": True,
                },
                "verdict": {"value": "VERDICT_UNDETECTED"},
                "threat_score": {"value": 1},
                "severity": {"value": "SEVERITY_NONE"},
                "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity.",
            },
        },
        "relationships": {
            "related_threat_actors": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/related_threat_actors?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/related_threat_actors",
                },
            },
            "software_toolkits": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/software_toolkits?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/software_toolkits",
                },
            },
            "campaigns": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/campaigns?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/campaigns",
                },
            },
            "comments": {
                "data": [{"type": "comment", "id": f"u-{ENRICH_URL_ID}-231049ee"}],
                "meta": {
                    "cursor": "Cs8BChEKBGRhdGUSCQjd46yQy-3_AhK1AWoRc352aXJ1c3RvdGFsY2xvdWRynwELEgNVUkwiQGRiYWUyZDAyMDRhYTQ4OWUyMzRlYjJmOTAzYTAxMjdiMTdjNzEyMzg2NDI4Y2FiMTJiODZjNWY2OGFhNzU4NjcMCxIHQ29tbWVudCJJZGJhZTJkMDIwNGFhNDg5ZTIzNGViMmY5MDNhMDEyN2IxN2M3MTIzODY0MjhjYWIxMmI4NmM1ZjY4YWE3NTg2Ny1iZDIwOGQ0YQwYACAB"
                },
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/comments?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/comments",
                    "next": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/comments?limit=20&cursor=Cs8BChEKBGRhdGUSCQjd46yQy-3_AhK1AWoRc352aXJ1c3RvdGFsY2xvdWRynwELEgNVUkwiQGRiYWUyZDAyMDRhYTQ4OWUyMzRlYjJmOTAzYTAxMjdiMTdjNzEyMzg2NDI4Y2FiMTJiODZjNWY2OGFhNzU4NjcMCxIHQ29tbWVudCJJZGJhZTJkMDIwNGFhNDg5ZTIzNGViMmY5MDNhMDEyN2IxN2M3MTIzODY0MjhjYWIxMmI4NmM1ZjY4YWE3NTg2Ny1iZDIwOGQ0YQwYACAB",
                },
            },
            "reports": {
                "data": [
                    {
                        "type": "collection",
                        "id": "report--815a1cc1c82742d68689ef6480d8f2ee2b385b3b288f2d890614e5522e492477",
                    }
                ],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/reports?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/reports",
                },
            },
            "collections": {
                "data": [
                    {
                        "type": "collection",
                        "id": "106db14ba76f8f141db690f2e0182146ea89a3a7d3850a14b7730dc932014aa5",
                    },
                    {
                        "type": "collection",
                        "id": "212db69792038394b8ecdaf484fdf1260b839d97590acf7468d959f33578eefe",
                    },
                    {
                        "type": "collection",
                        "id": "21f77f0ed9ed633e1d2c54c3498daa404ef837caf3c63054cc9368aed6b206e0",
                    },
                ],
                "meta": {"cursor": "eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9"},
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/collections?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/collections",
                    "next": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/collections?limit=20&cursor=eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9",
                },
            },
            "malware_families": {
                "data": [
                    {
                        "type": "collection",
                        "id": "analysis_virustotal_zenbox_redlinestealer",
                    },
                    {"type": "collection", "id": "analysis_virustotal_zenbox_xworm"},
                ],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/malware_families?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/malware_families",
                },
            },
            "vulnerabilities": {
                "data": [],
                "links": {
                    "self": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/relationships/vulnerabilities?limit=20",
                    "related": f"https://www.virustotal.com/api/v3/urls/{ENRICH_URL_ID}/vulnerabilities",
                },
            },
        },
    }
}

RELATIONSHIP_URL = "https://www.youtube.com/"

RELATIONSHIP_URL_ID = (
    base64.urlsafe_b64encode(RELATIONSHIP_URL.encode()).decode().rstrip("=")
)

RELATIONSHIP_API_RESPONSE = {
    "data": {
        "id": RELATIONSHIP_URL_ID,
        "type": "url",
        "links": {
            "self": f"https://www.virustotal.com/api/v3/urls/{RELATIONSHIP_URL_ID}"
        },
        "attributes": {
            "tld": "com",
            "first_submission_date": 1557160080,
            "last_final_url": "https://www.somedomain.com/this/is/my/url",
            "last_http_response_code": 200,
            "last_analysis_date": 1738938094,
            "threat_severity": {
                "version": "U3",
                "threat_severity_level": "SEVERITY_NONE",
                "threat_severity_data": {},
                "last_analysis_date": "1738938703",
                "level_description": "No severity score data",
            },
            "redirection_chain": ["http://www.somedomain.com/this/is/my/url"],
            "total_votes": {"harmless": 1, "malicious": 1},
            "last_http_response_content_length": 114,
            "url": "http://www.somedomain.com/this/is/my/url",
            "times_submitted": 66,
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 1,
                "undetected": 28,
                "harmless": 67,
                "timeout": 0,
            },
            "last_http_response_headers": {
                "Content-Length": "114",
                "Content-Type": "text/html",
                "Date": "Fri, 07 Feb 2025 14:26:36 GMT",
            },
            "title": "somedomain.com",
            "reputation": 0,
            "threat_names": [],
            "has_content": False,
            "favicon": {
                "raw_md5": "f3e260b62c4b891753fd57bf5fd075cc",
                "dhash": "e08c9a3b23a2ccf8",
            },
            "last_http_response_content_sha256": "6dc9c7fc93bb488bb0520a6c780a8d3c0fb5486a4711aca49b4c53fac7393023",
            "last_modification_date": 1738953881,
            "gti_assessment": {
                "severity": {"value": "SEVERITY_NONE"},
                "contributing_factors": {
                    "safebrowsing_verdict": "harmless",
                    "gti_confidence_score": 3,
                },
                "threat_score": {"value": 1},
                "verdict": {"value": "VERDICT_UNDETECTED"},
                "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity.",
            },
        },
    }
}

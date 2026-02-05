// Тест_ПровайдерJWT

Процедура ИсполняемыеСценарии() Экспорт
	ЮТТесты
		.ДобавитьТестовыйНабор("ПровайдерJWT", "Security,Auth,JWT")
			.ДобавитьСерверныйТест("СформироватьJWT_ВозвращаетТриЧасти")
			.ДобавитьСерверныйТест("СформироватьJWT_ДергаетПортКлючаПодписи_ОдинРаз")
			.ДобавитьСерверныйТест("СформироватьJWT_HeaderAlg_RS256")
			.ДобавитьСерверныйТест("СформироватьJWT_ПишетIssJtiSubAud")
			.ДобавитьСерверныйТест("СформироватьJWT_ФильтруетПустыеПолучатели")
			.ДобавитьСерверныйТест("СформироватьJWT_СчитаетIatExp")
			.ДобавитьСерверныйТест("СформироватьJWT_ДобавляетУтверждения")
	;
КонецПроцедуры

////////////////////////////////////////////////////////////////////////////////
// Настройка: порт + PEM
////////////////////////////////////////////////////////////////////////////////

Функция ПолучитьТестовыйPEM() Экспорт
	Возврат "-----BEGIN PRIVATE KEY-----
|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
|tbK7PRVC8eBOAJi3rTDW01M=
|-----END PRIVATE KEY-----"; 
КонецФункции

////////////////////////////////////////////////////////////////////////////////
// Helpers: данные токена
////////////////////////////////////////////////////////////////////////////////

Функция СделатьДанныеТокена() Экспорт
	Д = Новый Структура;

	Д.Вставить("Эмитент", "issuer-1");
	Д.Вставить("ИдентификаторТокена", "jti-123");

	Получатели = Новый Массив;
	Получатели.Добавить("aud-1");
	Получатели.Добавить("aud-2");
	Д.Вставить("Получатели", Получатели);

	Д.Вставить("КлючСопоставленияПользователя", "user-key-42");
	Д.Вставить("ВремяСозданияUTC", Дата(2026, 2, 1, 10, 0, 0));
	Д.Вставить("ВремяЖизниСек", 3600);

	Возврат Д;
КонецФункции

////////////////////////////////////////////////////////////////////////////////
// Helpers: base64url decode + parse JWT JSON
////////////////////////////////////////////////////////////////////////////////

Функция Base64UrlDecodeToString(Знач B64Url) Экспорт
	S = СтрЗаменить(B64Url, "-", "+");
	S = СтрЗаменить(S, "_", "/");

	Ост = СтрДлина(S) % 4;
	Если Ост = 2 Тогда
		S = S + "==";
	ИначеЕсли Ост = 3 Тогда
		S = S + "=";
	ИначеЕсли Ост = 1 Тогда
		ВызватьИсключение "Некорректная base64url строка.";
	КонецЕсли;

	ДД = Base64Значение(S);
	Возврат ПолучитьСтрокуИзДвоичныхДанных(ДД, КодировкаТекста.UTF8);
КонецФункции

Функция РазобратьJWT(Знач JWTСтрока) Экспорт
	Части = СтрРазделить(JWTСтрока, ".", Ложь);
	Если Части.Количество() <> 3 Тогда
		ВызватьИсключение "JWT должен состоять из 3 частей.";
	КонецЕсли;

	HeaderJson = Base64UrlDecodeToString(Части[0]);
	PayloadJson = Base64UrlDecodeToString(Части[1]);

	Header = УтилитыJSON.JSONВСтруктуру(HeaderJson);
	Payload = УтилитыJSON.JSONВСтруктуру(PayloadJson);

	Возврат Новый Структура("Header,Payload,SignaturePart", Header, Payload, Части[2]);
КонецФункции

////////////////////////////////////////////////////////////////////////////////
// Helpers: подготовка портов + мок порта ключа подписи (Мокито)
////////////////////////////////////////////////////////////////////////////////

Функция СделатьПортыСМокомКлючаПодписи() Экспорт
	PEM = ПолучитьТестовыйPEM();

	// Мокаем общий модуль порта: на любой Порты -> вернуть PEM
	Мокито.Обучение(АдаптерКлючПодписи, Истина)
		.Когда("КлючПодписиJWT")
		.Вернуть(PEM)
		.Прогон();
	
	Порты = Новый Структура;
	Порты.Вставить("КлючПодписи", АдаптерКлючПодписи);
	//Порты.Вставить("ХранилкаКлючей", Константы.СекретныйКлючПодписиJWT);

	Возврат Новый Структура("Порты", Порты);
КонецФункции

////////////////////////////////////////////////////////////////////////////////
// Тесты
////////////////////////////////////////////////////////////////////////////////

Процедура СформироватьJWT_ВозвращаетТриЧасти() Экспорт
	Данные = СделатьДанныеТокена();
	Обвязка = СделатьПортыСМокомКлючаПодписи();

	JWT = ПровайдерJWT.СформироватьJWT(Данные, Обвязка.Порты.КлючПодписи);

	ЮТест.ОжидаетЧто(ТипЗнч(JWT)).Равно(Тип("Строка"));
	ЮТест.ОжидаетЧто(СтрДлина(СокрЛП(JWT)) > 0).ЭтоИстина();

	Части = СтрРазделить(JWT, ".", Ложь);
	ЮТест.ОжидаетЧто(Части.Количество()).Равно(3);
	ЮТест.ОжидаетЧто(СтрДлина(СокрЛП(Части[2])) > 0).ЭтоИстина();
КонецПроцедуры

Процедура СформироватьJWT_ДергаетПортКлючаПодписи_ОдинРаз() Экспорт
	Данные = СделатьДанныеТокена();
	Обвязка = СделатьПортыСМокомКлючаПодписи();

	_ = ПровайдерJWT.СформироватьJWT(Данные, Обвязка.Порты.КлючПодписи);

	// Проверяем вызов порта
	Мокито.Проверить(Обвязка.Порты.КлючПодписи)
		.КоличествоВызовов("КлючПодписиJWT")
		.Равно(1);
КонецПроцедуры

Процедура СформироватьJWT_HeaderAlg_RS256() Экспорт
	Данные = СделатьДанныеТокена();
	Обвязка = СделатьПортыСМокомКлючаПодписи();

	JWT = ПровайдерJWT.СформироватьJWT(Данные, Обвязка.Порты.КлючПодписи);
	Разбор = РазобратьJWT(JWT);

	ЮТест.ОжидаетЧто(Разбор.Header).Свойство("alg").Равно("RS256");
КонецПроцедуры

Процедура СформироватьJWT_ПишетIssJtiSubAud() Экспорт
	Данные = СделатьДанныеТокена();
	Обвязка = СделатьПортыСМокомКлючаПодписи();

	JWT = ПровайдерJWT.СформироватьJWT(Данные,Обвязка.Порты.КлючПодписи);
	Payload = РазобратьJWT(JWT).Payload;

	ЮТест.ОжидаетЧто(Payload).Свойство("iss").Равно("issuer-1");
	ЮТест.ОжидаетЧто(Payload).Свойство("jti").Равно("jti-123");

	// Обычно это claim "sub"
	ЮТест.ОжидаетЧто(Payload).Свойство("sub").Равно("user-key-42");

	// aud может быть строкой/массивом — хотя бы должен быть
	Ауд = Неопределено;
	ЮТест.ОжидаетЧто(Payload.Свойство("aud", Ауд)).ЭтоИстина();
КонецПроцедуры

Процедура СформироватьJWT_ФильтруетПустыеПолучатели() Экспорт
	Данные = СделатьДанныеТокена();
	Данные.Получатели.Добавить("");
	Данные.Получатели.Добавить("   ");
	Данные.Получатели.Добавить(Неопределено);

	Обвязка = СделатьПортыСМокомКлючаПодписи();

	JWT = ПровайдерJWT.СформироватьJWT(Данные,Обвязка.Порты.КлючПодписи);
	Payload = РазобратьJWT(JWT).Payload;

	Ауд = Неопределено;
	ЮТест.ОжидаетЧто(Payload.Свойство("aud", Ауд)).ЭтоИстина();

	Если ТипЗнч(Ауд) = Тип("Массив") Тогда
		Для Каждого Элемент Из Ауд Цикл
			ЮТест.ОжидаетЧто(СтрДлина(СокрЛП(Строка(Элемент))) > 0).ЭтоИстина();
		КонецЦикла;
	ИначеЕсли ТипЗнч(Ауд) = Тип("Строка") Тогда
		ЮТест.ОжидаетЧто(СтрДлина(СокрЛП(Ауд)) > 0).ЭтоИстина();
	КонецЕсли;
КонецПроцедуры

Процедура СформироватьJWT_СчитаетIatExp() Экспорт
	Данные = СделатьДанныеТокена();
	Данные.ВремяСозданияUTC = Дата(2026, 2, 1, 10, 0, 0);
	Данные.ВремяЖизниСек = 3600;

	Обвязка = СделатьПортыСМокомКлючаПодписи();

	JWT = ПровайдерJWT.СформироватьJWT(Данные, Обвязка.Порты.КлючПодписи);
	Payload = РазобратьJWT(JWT).Payload;

	Эпоха = Дата(1970, 1, 1, 0, 0, 0);
	ОжидIat = (Данные.ВремяСозданияUTC - Эпоха);

	ЮТест.ОжидаетЧто(Payload).Свойство("iat").Равно(ОжидIat);
	ЮТест.ОжидаетЧто(Payload).Свойство("exp").Равно(ОжидIat + 3600);
КонецПроцедуры

Процедура СформироватьJWT_ДобавляетУтверждения() Экспорт
	Данные = СделатьДанныеТокена();

	Claims = Новый Структура;
	Claims.Вставить("role", "admin");
	Claims.Вставить("scope", "read");
	Claims.Вставить("x", 1);
	Данные.Вставить("Утверждения", Claims);

	Обвязка = СделатьПортыСМокомКлючаПодписи();

	JWT = ПровайдерJWT.СформироватьJWT(Данные, Обвязка.Порты.КлючПодписи);
	Payload = РазобратьJWT(JWT).Payload;

	ЮТест.ОжидаетЧто(Payload).Свойство("role").Равно("admin");
	ЮТест.ОжидаетЧто(Payload).Свойство("scope").Равно("read");
	ЮТест.ОжидаетЧто(Payload).Свойство("x").Равно(1);
КонецПроцедуры

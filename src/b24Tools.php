<?php

namespace webmensru\b24tools;

use yii\base\BaseObject;
use Yii;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

/**
 * Description of b24connector
 *
 * @author Админ
 */
class b24Tools extends \yii\base\BaseObject {

    /**
    * Max calls in one batch
    */
    public  const MAX_BATCH_CALLS = 50;
    private $b24PortalTable;
    private $arAccessParams;
    private $b24_error = '';
    private $arB24App;
    private $arScope;
    private $applicationId;
    private $applicationSecret;

    /** 
    * Получение данные аутентификации из БД
    * Выполняет комманду выбора записи из таблицы b24PortalTable
    * @param string $domain Название портала
    * @return Запись из сущности, и false, если ничего не выбрано
    */
    private function getAuthFromDB($domain) {
        $res = Yii::$app->db
                ->createCommand("SELECT * FROM " . $this->b24PortalTable . " WHERE PORTAL = '" . $domain . "'")
                ->queryOne();
        return $res;
    }

    /**
    * Добавление данных аутентификации из БД
    * Вставляет записи в таблицу с токенами
    * @param string $tableName Название сущности
    * @param array $auth Массив данных аутентификации
    * @return Количество строк, которые были вставлены
    */
    public function addAuthToDB($tableName, $auth) {
        $res = Yii::$app->db
                ->createCommand()
                ->insert($tableName, [
                    'PORTAL' => $auth['domain'],
                    'ACCESS_TOKEN' => $auth['access_token'],
                    'REFRESH_TOKEN' => $auth['refresh_token'],
                    'MEMBER_ID' => $auth['member_id'],
                    'DATE' => date("Y-m-d"),
                        ]
                )
                ->execute();
        return $res;
    }

    /** 
    * Обновление данных аутентификации в БД
    * Выполняет комманду обновления данных аутентификации в таблицу с токенами
    * @param array $auth Массив данных аутентификации
    * @return Количество строк, которые были обновлены
    */
    public function updateAuthToDB($auth) {
        if ($this->b24PortalTable) {
            $res = Yii::$app->db
                    ->createCommand() 
                    ->update($this->b24PortalTable, [ 
                        'ACCESS_TOKEN' => $auth['access_token'],
                        'REFRESH_TOKEN' => $auth['refresh_token'],
                        'DATE' => date("Y-m-d"),
                            ], ['PORTAL' => $auth['domain'],
                        'MEMBER_ID' => $auth['member_id'],]
                    )
                    ->execute();
            return $res;
        }
    }

    /** 
    * Перенос данных из БД в массив
    * Переносит данные из БД в массив по определённым ключам
    * @param array $arAccessParams Ассоциативный массив, из которого будем переносить
    * @return Ассоциативный массив данных, в которых наименование ключей приведены к нижнему регистру
    */
    private function prepareFromDB($arAccessParams) {
        $arResult = array();
        $arResult['domain'] = $arAccessParams['PORTAL'];
        $arResult['member_id'] = $arAccessParams['MEMBER_ID'];
        $arResult['refresh_token'] = $arAccessParams['REFRESH_TOKEN'];
        $arResult['access_token'] = $arAccessParams['ACCESS_TOKEN'];
        return $arResult;
    }

    /** 
    * Подготовка для AJAX запроса
    * Перенос токенов из ассоциативного массива в поле класса
    * @param  array $arRequest Ассоциативный массив токенов
    * @return Перенесённый ассоциативный массив токенов
    */
    public function prepareFromAjaxRequest($arRequest) {
        $arResult = array();
        $arResult['domain'] = $arRequest['domain'];
        $arResult['member_id'] = $arRequest['member_id'];
        $arResult['refresh_token'] = $arRequest['refresh_token'];
        $arResult['access_token'] = $arRequest['access_token'];
        $this->arAccessParams = $arResult;
        return $arResult;
    }

    /** 
    * Подготовка для запроса хендлера
    * Перенос токенов из ассоциативного массива в поле класса
    * @param array $arRequest Ассоциативный массив токенов
    * @return Перенесённый ассоциативный массив токенов
    */
    public function prepareFromHandlerRequest($arRequest) {
        $arResult = array();
        $arResult['domain'] = $arRequest['domain'];
        $arResult['member_id'] = $arRequest['member_id'];
        $arResult['access_token'] = $arRequest['access_token'];
        $arResult['refresh_token'] = ' ';
        $this->arAccessParams = $arResult;
        return $arResult;
    }

    /** 
    * Подготовка для запроса
    * Перенос токенов из ассоциативного массива в поле класса с проверкой на существование POST или GET запроса
    * @param array $arRequestPost POST-запрос массива токенов (может быть не задан)
    * @param array $arRequestGet GET-запрос массива токенов (может быть не задан)
    * @return Перенесённый ассоциативный массив токенов
    */
    public function prepareFromRequest($arRequestPost = null, $arRequestGet = null) {
        if (!$arRequestPost or !$arRequestGet) {
            return array();
        }
        $arResult = array();
        $arResult['domain'] = $arRequestGet['DOMAIN'];
        $arResult['member_id'] = $arRequestPost['member_id'];
        $arResult['refresh_token'] = $arRequestPost['REFRESH_ID'];
        $arResult['access_token'] = $arRequestPost['AUTH_ID'];
        $this->arAccessParams = $arResult;
        return $arResult;
    }

    /** 
    * Проверка аутентификации с битриксом
    * Проверяет токены и обновляет, если токен устаревший
    * @param array $arScope массив области действия приложения (может быть не задан)
    * @return Логическая переменная, соответствующая наличию или отстутствию ошибок при проверке подключения
    */
    public function checkB24Auth($arScope = array()) {

        if (!is_array($arScope)) {
            $arScope = array();
        }
        if (!in_array('user', $arScope)) {
            $arScope[] = 'user';
        }

        $isTokenRefreshed = false;

        $this->arB24App = $this->getBitrix24($this->arAccessParams, $isTokenRefreshed, $this->b24_error, $arScope); 
        if ($isTokenRefreshed and $this->b24PortalTable) {
            $this->updateAuthToDB($this->arAccessParams);
        }
        return $this->b24_error === true;
    }

    /** 
    * Устанавливает все данные из битрикса
    * Проверяет токены и обновляет, если токен устаревший, а также создаёт логи
    * @param array &$arAccessData массив токенов для приложения
    * @param bool &$btokenRefreshed информация об обновление токенов
    * @param \Exception &$errorMessage Объект сообщения об ошбке для последующего вывода в логи
    * @param array $arScope массив области действия приложения (может быть не задан)
    * @return Объект Bitrix24 из bitrix24-php-sdk
    */
    private function getBitrix24(&$arAccessData, &$btokenRefreshed, &$errorMessage, $arScope = array()) {
        $log = new Logger('bitrix24');
        $log->pushHandler(new StreamHandler('log/b24/' . date('Y_m_d') . '.log', Logger::DEBUG));

        $btokenRefreshed = null;

        $obB24App = new \Bitrix24\Bitrix24(false, $log);
        if (!is_array($arScope)) {
            $arScope = array();
        }
        if (!in_array('user', $arScope)) {
            $arScope[] = 'user';
        }
        $obB24App->setApplicationScope($arScope);
        $obB24App->setApplicationId($this->applicationId);
        $obB24App->setApplicationSecret($this->applicationSecret);

        // set user-specific settings
        $obB24App->setDomain($arAccessData['domain']);
        $obB24App->setMemberId($arAccessData['member_id']);
        $obB24App->setRefreshToken($arAccessData['refresh_token']);
        $obB24App->setAccessToken($arAccessData['access_token']);
        try {
            $resExpire = $obB24App->isAccessTokenExpire();
        } catch (\Exception $e) {
            $errorMessage = $e->getMessage();
        }
        if ($resExpire) {
            Yii::warning('Access - expired', 'b24Tools');

            try {
                $result = $obB24App->getNewAccessToken();
            } catch (\Exception $e) {
                $errorMessage = $e->getMessage();
            }

            if ($result === false) {
                $errorMessage = 'access denied';
            } elseif (is_array($result) && array_key_exists('access_token', $result) && !empty($result['access_token'])) {
                $arAccessData['refresh_token'] = $result['refresh_token'];
                $arAccessData['access_token'] = $result['access_token'];
                $obB24App->setRefreshToken($arAccessData['refresh_token']);
                $obB24App->setAccessToken($arAccessData['access_token']);
                $this->updateAuthToDB($this->arAccessParams);
                //Yii::warning('Access - refreshed', 'b24Tools');
                $btokenRefreshed = true;
            } else {
                $btokenRefreshed = false;
            }
        } else {
            $btokenRefreshed = false;
        }
        return $obB24App;
    }

    /** 
    * Связь приложения и битрикса
    * Проверяет токены и обновляет, если токен устаревший
    * @param string $applicationId Код приложения
    * @param string $applicationSecret Ключ приложения
    * @param string $tableName Название таблицы (может быть не указано)
    * @param string $domain Название портала (может быть не указано)
    * @param array $arScope массив области действия приложения (может быть не задан)
    * @param array $autch Информация об аутентификации
    * @return Объект приложения, связанного с битриксом
    */
    public function connect($applicationId, $applicationSecret, $tableName = '', $domain = null, $arScope = array(), $autch = null) {//Связь с БД
        $this->applicationId = $applicationId;//Устанавливаем данные у данного объекта
        $this->applicationSecret = $applicationSecret;
        $this->b24PortalTable = $tableName;
        if ($autch === null) {//Если аутентификации не было
            $res = $this->getAuthFromDB($domain); //Нужно добавить проверку res             
            if (!$res) {
                Yii::error('getAuthFromDB(' . $domain . ')=false');
                return false;
            }

            $this->arAccessParams = $this->prepareFromDB($res);//устанавливаем $arAccessParams в удобоваримый для БД вид 
        } else {
            $this->arAccessParams = $autch;
        }
        $this->b24_error = $this->checkB24Auth($arScope);//Проверка на аутентификацию приложения у битрикса
        if ($this->b24_error != '') {
            Yii::error('DB auth error: ' . $this->b24_error);//Вывод в логе БД
            return false;
        }
        return $this->arB24App;
    }

    public static function toBool($data) {//Преобразование в битриксовскую логическую переменную
        return $data?'Y':'N';
    }
    
    public static function boolToInt($data) {       
        return $data=='Y'?1:0;
    }
    
}

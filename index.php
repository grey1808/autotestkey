<?php
//set_include_path (get_include_path (). PATH_SEPARATOR. 'phpseclib1.0.18');
//include_once('Net/SSH2.php');
include_once ('phpseclib1.0.18/Net/SSH2.php');


class DataBase {
    public $localhost = '10.226.1.130'; // база данных
    public $username = 'dbuser';
    public $password = 'dbpassword';
    public $database = 'rutoken';
    private static $db = null; // Единственный экземпляр класса, чтобы не создавать множество подключений
    private $mysqli; // Идентификатор соединения
    private $sym_query = "{?}"; // "Символ значения в запросе"

    /* Получение экземпляра класса. Если он уже существует, то возвращается, если его не было, то создаётся и возвращается (паттерн Singleton) */
    public static function getDB() {
        if (self::$db == null) self::$db = new DataBase();
        return self::$db;
    }

    /* private-конструктор, подключающийся к базе данных, устанавливающий локаль и кодировку соединения */
    private function __construct() {
        $this->mysqli = new mysqli($this->localhost, $this->username, $this->password, $this->database);
        $this->mysqli->query("SET lc_time_names = 'ru_RU'");
        $this->mysqli->query("SET NAMES 'utf8'");
    }

    /* Вспомогательный метод, который заменяет "символ значения в запросе" на конкретное значение, которое проходит через "функции безопасности" */
    private function getQuery($query, $params) {
        if ($params) {
            for ($i = 0; $i < count($params); $i++) {
                $pos = strpos($query, $this->sym_query);
                $arg = "'".$this->mysqli->real_escape_string($params[$i])."'";
                $query = substr_replace($query, $arg, $pos, strlen($this->sym_query));
            }
        }
        return $query;
    }

    /* SELECT-метод, возвращающий таблицу результатов */
    public function select($query, $params = false) {
        $result_set = $this->mysqli->query($this->getQuery($query, $params));
        if (!$result_set) return false;
        return $this->resultSetToArray($result_set);
    }

    /* SELECT-метод, возвращающий одну строку с результатом */
    public function selectRow($query, $params = false) {
        $result_set = $this->mysqli->query($this->getQuery($query, $params));
        if ($result_set->num_rows != 1) return false;
        else return $result_set->fetch_assoc();
    }

    /* SELECT-метод, возвращающий значение из конкретной ячейки */
    public function selectCell($query, $params = false) {
        $result_set = $this->mysqli->query($this->getQuery($query, $params));
        if ((!$result_set) || ($result_set->num_rows != 1)) return false;
        else {
            $arr = array_values($result_set->fetch_assoc());
            return $arr[0];
        }
    }

    /* НЕ-SELECT методы (INSERT, UPDATE, DELETE). Если запрос INSERT, то возвращается id последней вставленной записи */
    public function query($query, $params = false) {
        $success = $this->mysqli->query($this->getQuery($query, $params));
        if ($success) {
            if ($this->mysqli->insert_id === 0) return true;
            else return $this->mysqli->insert_id;
        }
        else return false;
    }

    /* Преобразование result_set в двумерный массив */
    private function resultSetToArray($result_set) {
        $array = array();
        while (($row = $result_set->fetch_assoc()) != false) {
            $array[] = $row;
        }
        return $array;
    }

    /* При уничтожении объекта закрывается соединение с базой данных */
    public function __destruct() {
        if ($this->mysqli) $this->mysqli->close();
    }

}

class fOpen{
      public function  file($string){
          $fd = fopen("text.txt", 'a+') or die("не удалось создать файл");
          fwrite($fd, $string."\n");
          fclose($fd);
      }
};

class autoStart{


    public function getIpList(){ // полчение клиентов всех
        $db = DataBase::getDB(); // Создаём объект базы данных
        $query = "SELECT * FROM `iplist` WHERE  ipaddress NOT IN('$db->server')";
        $table = $db->select($query); // Запрос явно должен вывести таблицу, поэтому вызываем метод select()
        return $table;
    }


    public function setEventUpdate($iplist_id,$ssh,$datetime,$user_id){ // запись в таблицу event результата проверки ключа
        $db = DataBase::getDB(); // Создаём объект базы данных
        $query = "INSERT INTO event(iplist_id,event,datetime,user_id) VALUES('$iplist_id','$ssh','$datetime','$user_id')";
        $table = $db->query($query); // Запрос явно должен вывести таблицу, поэтому вызываем метод select()
//        printf($table);
        return $table;
    }


    /*
     * Проверка
     * если статус ключа not plugged, shared, то необходимо проверить есть ли еще токен поключенный
     */

    public function ChekStatusKey($arr,$ipaddress,$username,$password){
        foreach ($arr as $key => $i){
            if(stristr($i,'Status: plugged'))
                if(stristr($arr[$key-2], 'Rutoken') || stristr($arr[$key-2], 'JaCarta')){
                    $command = 'usbsrv -share '.trim(stristr($arr[$key - 2],':',true)); // получаем порт
                    $resoult = $this->actionComandRestart($ipaddress,$username,$password,$command);
                    if(stristr($resoult,'SUCCESSFUL')){
                        return trim(stristr($arr[$key - 2],':',true)); // возвращаем порт
                    }
                }
        }
    }

    /*
     * Проверяем есть ли статус Status: plugged, shared
     */
    public function ChekStatusKeyShared($arr){
        foreach ($arr as $key => $i){
            if(stristr($i,'Status: plugged, shared'))
                if(stristr($arr[$key-2], 'Rutoken') || stristr($arr[$key-2], 'JaCarta')){
                    return trim(stristr($arr[$key - 2],':',true)); // возвращаем порт
                }
        }
    }

    /**
     * Проверка клиента на статус ключа    *
     */
    public function actionGetOne($id,$ipaddress,$username,$password){ // проверяем клиента

        try{
            $access = $this->actionCommand($ipaddress,$username,$password);
            if(is_array($access)){
                foreach ($access as $key => $item) {
                    if(stristr($item, 'not plugged, shared')){
//                        $ssh = 'Ключ не подключен (носитель не вставлен)';
                        $port = $this->ChekStatusKey($access,$ipaddress,$username,$password);
                        $port2 = $this->ChekStatusKeyShared($access);
                        if ($port){ // проверяем есть ли
                            $ssh = 'Изменился порт USB с '.trim(stristr($access[$key - 2],':',true)).' на '.$port;
                        }else if ($port2){
                            $ssh = 'Ключ вставлен, но недоступен, Порт: '.$port2;
                        }else{
                            $ssh = 'Ключ не подключен (носитель не вставлен)';
                        }
                    }else if(stristr($item, 'plugged, shared')) {
//                        $ssh = 'Ключ вставлен, но недоступен, Порт: '.trim(stristr($access[$key - 2],':',true));
                        $port = trim(stristr($access[$key - 2],':',true));
                        $r = $this->actionRestartClient($id,$port,$ipaddress,$username,$password);
                        if($r){
                            $ssh = 'Ключ вставлен, но недоступен, Порт: '.trim(stristr($access[$key - 2],':',true)).' но был успешно переподключен';
                        }else{
                            $ssh = 'Ключ вставлен, но недоступен, Порт: '.trim(stristr($access[$key - 2],':',true));
                        }
                    }else if(stristr($item, 'Status: in use by')) {
                        $ssh = 'Ключ подключен! Порт: '.trim(stristr($access[$key - 2],':',true));
                    }
                }
            }else{
                $ssh = $access;
            }
        }catch (Exception $e){
            $ssh = 'ip адрес недоступен';
        }

        $start = new autoStart();
        $arr = $start->setEventUpdate($id,$ssh,date("Y-m-d H:i:s"),0);
        if(!$arr){
            $f = new fOpen();
            $string = 'Не удалось записать значение в БД id = '.$id .' Результат '.$ssh .'Дата '.date("Y-m-d H:i:s");
            $f->file($string);
        }

        return $ssh;
    }


    /**
     *  Команды ssh
     *
     */
    public function actionCommand($host,$username,$password){

        $console = "usbsrv -list";
        $ssh = new Net_SSH2($host);
        if (!$ssh->login($username, $password)) {
            $line = 'Логин не верный';
        }else{
            $lin = $ssh->exec($console);
            $line = explode("\n", $lin);
        }



        return $line;
    }

    /*
 * Команада для переподключения
 *
 * */
    public function actionComandRestart($server_ip,$server_username,$serverpassword,$console){ // удалить ключ

        $ssh = new Net_SSH2($server_ip);
        if (!$ssh->login($server_username, $serverpassword)) {
            $line = false;
        }else{
            $line = $ssh->exec($console);
        }




        return $line;
    }

    /**
     *  Переподключить клиента на сервере
     * Кнопка "Переподключить"
     **/
    public function actionRestartClient($id, $port,$clientipaddress){ // переподключение ключа Кнопка "Переподключить"

        $db = DataBase::getDB(); // Создаём объект базы данных
        $query = "SELECT * FROM `iplist` WHERE server_id=$id";
        $server = $db->select($query);
        $server_id = $server['id']; // Получаем id сервер
        $query = "SELECT * FROM `server` WHERE id=$server_id";
        $s = $db->select($query); // Запрос явно должен вывести таблицу, поэтому вызываем метод select()

        $serverusername = $s['username'];
        $serverpassword = $s['password'];
        $serveripaddress = $s['ipaddress'];

        $console = "usbclnt -remserver ".$clientipaddress.":32032";
        $remserver = $this->actionComandRestart(
            $serverusername,
            $serverusername,
            $serverpassword,
            $console
        );// удалить с сервера

        $console = "usbclnt -addserver ".$clientipaddress.":32032";
        $addserver = $this->actionComandRestart(
            $serveripaddress,
            $serverusername,
            $serverpassword,
            $console
        );// добавить на сервер
        if(stristr($addserver,'OPERATION SUCCESSFUL')){
            $console = "usbclnt -list";
            $usbclnt_list = $this->actionComandRestart(
                $serveripaddress,
                $serverusername,
                $serverpassword,
                $console
            );// добавить на сервер
            if(stristr($usbclnt_list,'USB CLIENT OPERATION SUCCESSFUL')){
                $usbclnt_lis = explode("\n", $usbclnt_list); // преобразуем в массив
                foreach ($usbclnt_lis as $key => $item) {
                    if(stristr($item,$clientipaddress)){
                        $resoult = trim(stristr($item,':',true));
                    }
                }
                $console = "usbclnt -connect $resoult-$port";
                $usbclnt_connect = $this->actionComandRestart(
                    $serveripaddress,
                    $serverusername,
                    $serverpassword,
                    $console
                );// подключение к серверу
                if(stristr($usbclnt_connect,'OPERATION SUCCESSFUL')){
                    $console = "usbclnt -autoconnecton $resoult-$port";
                    $autoconnecton = $this->actionComandRestart(
                        $serveripaddress,
                        $serverusername,
                        $serverpassword,
                        $console
                    );// подключение к серверу
                    if(stristr($autoconnecton,'OPERATION SUCCESSFUL')){
//                        $f = new fOpen();
//                        $string = 'Выполнено успешное переподключение. '. date("Y-m-d H:i:s").' ip адресс'.$clientipaddress;
//                        $f->file($string);
                        return true;
                    }else{
                        $f = new fOpen();
                        $string = 'Не удалось автоматически переподключить ключ. '. date("Y-m-d H:i:s").' ERROR usbclnt -autoconnecton'.$autoconnecton;
                        $f->file($string);
                        return false;
                    }

                }else{
                    $f = new fOpen();
                    $string = 'Не удалось автоматически переподключить ключ. '. date("Y-m-d H:i:s").' ERROR usbclnt -connect'.$usbclnt_connect;
                    $f->file($string);
                    return false;
                }

            }else{
                $f = new fOpen();
                $string = 'Не удалось автоматически переподключить ключ. '. date("Y-m-d H:i:s").' ERROR usbclnt -list'.$usbclnt_list;
                $f->file($string);
                return false;
            }

        }else{
            $f = new fOpen();
            $string = ' Выполните переподключение снова '. date("Y-m-d H:i:s").' usbclnt -list '.$addserver;
            $f->file($string);
            return false;

        }





    } // переподключение ключа на сервере

}


$start = new autoStart();
$iplist = $start->getIpList();
$count = 0;
foreach ($iplist as $item){
    $resoult = $start->actionGetOne($item['id'],$item['ipaddress'],$item['username'],$item['password']);
    $count++;
    print $item['ipaddress'].' - '.$resoult."\n";
}
$f = new fOpen();
$string = 'Проверка выполнена '. date("d.m.Y H:i:s".' Количество итераций '.$count);
$f->file($string);




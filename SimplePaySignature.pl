use Digest::MD5  qw(md5 md5_hex);
use Digest::SHA  qw(sha256 sha256_hex sha512 sha512_hex);

# Процедура получения хеша от заданной строки заданным алгоритмом
sub make_hash{

        my ($data, $algo) = (shift, shift);
        $result = "";
        if($algo eq "md5"){
            $result = md5_hex($data);
        }
        if($algo eq "sha256"){
            $result = sha256_hex($data);
        }
        if($algo eq "sha512"){
            $result = sha512_hex($data);
        }

        return $result;
}

# Процедура формирования строки конкатенации
sub make_concat_string{

    my ($script_name, $secret_key) = (shift, shift);
    my %data = %{shift()};
    $concat_string = "";
    foreach my $name (sort keys %data) {
          $concat_string .= $data{$name}.";";
    }
    return $script_name.";".$concat_string.$secret_key;
}

# Процедура для формирования строки подписи
sub make_signature_string{
    my ($script_name, $secret_key, $hash_algo) = (shift, shift, shift);
    my %data = %{shift()};
    return make_hash(make_concat_string($script_name,$secret_key,\%data),$hash_algo);
}

#
# Пример формирования подписи
#
my %params = (
    sp_outlet_id => 2,
    sp_amount => "100",
    sp_description => "Назначение платежа",
    sp_salt => "123321"
);

print make_concat_string("payment","mykey",\%params) . "\n";
print make_signature_string("payment","mykey","md5",\%params) . "\n";
print make_signature_string("payment","mykey","sha256",\%params) . "\n";
print make_signature_string("payment","mykey","sha512",\%params) . "\n";

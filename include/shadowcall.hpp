#ifndef SHADOWCALL_SHADOWCALL_HPP
#define SHADOWCALL_SHADOWCALL_HPP

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <windows.h>

namespace shadow {
    namespace detail {
        class address_t {
          public:
            address_t() = default;
            ~address_t() = default;

            address_t(std::nullptr_t) {}

            address_t(const std::uintptr_t address)
                : _address(address) {
            }

            address_t(const void* address)
                : _address(reinterpret_cast<std::uintptr_t>(address)) {
            }

            address_t(const address_t& other) {
                if (this != &other)
                    _address = other._address;
            }

            auto operator=(const address_t& other) -> address_t& {
                if (this != &other)
                    _address = other._address;

                return *this;
            }

            operator void*() const {
                return reinterpret_cast<void*>(_address);
            }

            operator std::uintptr_t() const {
                return _address;
            }

            operator bool() const {
                return _address != 0;
            }

            template <typename Ret = address_t>
            auto as() const -> Ret {
                return Ret(_address);
            }

            template <typename Ret = address_t>
            auto offset(const std::ptrdiff_t offset) const -> Ret {
                return Ret(_address + offset);
            }

            template <typename Ret = address_t>
            auto get(std::size_t deref_count = 1) const -> Ret {
                std::uintptr_t return_address = _address;
                while (deref_count--)
                    if (return_address)
                        return_address = *reinterpret_cast<std::uintptr_t*>(return_address);

                return Ret(return_address);
            }

            template <typename Ret = address_t>
            auto jump(const std::ptrdiff_t offset_to_rel32 = 1) const -> Ret {
                std::uintptr_t return_address = _address + offset_to_rel32;
                return_address += *reinterpret_cast<std::int32_t*>(return_address);
                return_address += sizeof(std::int32_t);

                return Ret(return_address);
            }

            auto operator<=>(const address_t& other) const = default;

            auto operator+=(const address_t& other) -> address_t& {
                _address += other._address;
                return *this;
            }

            auto operator-=(const address_t& other) -> address_t& {
                _address -= other._address;
                return *this;
            }

          private:
            std::uintptr_t _address = 0;
        };

        namespace hash {
            using fnv1a64_t = std::uint64_t;

            constexpr std::uint64_t kFnvOffsetBasis = 0xcbf29ce484222325;
            constexpr std::uint64_t kFnvPrime = 0x100000001b3;

            constexpr auto fnv1a64(const char* data, const std::size_t size) -> fnv1a64_t {
                fnv1a64_t hash = kFnvOffsetBasis;
                for (std::size_t idx = 0; idx < size; ++idx) {
                    hash ^= data[idx];
                    hash *= kFnvPrime;
                }

                return hash;
            }

            constexpr auto fnv1a64(const std::string& str) -> fnv1a64_t {
                return fnv1a64(str.data(), str.length());
            }

            constexpr auto fnv1a64(const std::string_view str) -> fnv1a64_t {
                return fnv1a64(str.data(), str.length());
            }
        } // namespace hash

        namespace win
        {
            struct list_entry_t {
                list_entry_t* flink;
                list_entry_t* blink;
            };

            struct peb_ldr_data_t {
                std::uint32_t length;
                std::uint8_t initialized;
                void* ss_handle;
                list_entry_t in_load_order_module_list;
                list_entry_t in_memory_order_module_list;
                list_entry_t in_initialization_order_module_list;
                void* entry_in_progress;
            };

            struct peb_t {
                std::uint8_t inherited_address_space;
                std::uint8_t read_image_file_exec_options;
                std::uint8_t being_debugged;
                std::uint8_t bit_field;
                std::uint32_t image_uses_large_pages : 1;
                std::uint32_t is_protected_process : 1;
                std::uint32_t is_legacy_process : 1;
                std::uint32_t is_image_dynamically_relocated : 1;
                std::uint32_t spare_bites : 4;
                void* mutant;
                void* image_base_address;
                peb_ldr_data_t* ldr;
            };

            struct unicode_string_t {
                std::uint16_t length;
                std::uint16_t maximum_length;
                wchar_t* buffer;
            };

            struct ldr_data_table_entry_t {
                list_entry_t in_load_order_links;
                list_entry_t in_memory_order_links;
                list_entry_t in_initialization_order_links;
                void* dll_base;
                void* entry_point;
                std::uint32_t size_of_image;
                unicode_string_t full_dll_name;
                unicode_string_t base_dll_name;
            };

            struct image_dos_header_t {
                std::uint16_t e_magic;
                std::uint16_t e_cblp;
                std::uint16_t e_cp;
                std::uint16_t e_crlc;
                std::uint16_t e_cparhdr;
                std::uint16_t e_minalloc;
                std::uint16_t e_maxalloc;
                std::uint16_t e_ss;
                std::uint16_t e_sp;
                std::uint16_t e_csum;
                std::uint16_t e_ip;
                std::uint16_t e_cs;
                std::uint16_t e_lfarlc;
                std::uint16_t e_ovno;
                std::uint16_t e_res[4];
                std::uint16_t e_oemid;
                std::uint16_t e_oeminfo;
                std::uint16_t e_res2[10];
                std::uint32_t e_lfanew;
            };

            struct image_file_header_t {
                std::uint16_t machine;
                std::uint16_t number_of_sections;
                std::uint32_t time_date_stamp;
                std::uint32_t pointer_to_symbol_table;
                std::uint32_t number_of_symbols;
                std::uint16_t size_of_optional_header;
                std::uint16_t characteristics;
            };

            struct image_data_directory_t {
                std::uint32_t virtual_address;
                std::uint32_t size;
            };

            struct image_optional_header64_t {
                std::uint16_t magic;
                std::uint8_t major_linker_version;
                std::uint8_t minor_linker_version;
                std::uint32_t size_of_code;
                std::uint32_t size_of_initialized_data;
                std::uint32_t size_of_uninitialized_data;
                std::uint32_t address_of_entry_point;
                std::uint32_t base_of_code;
                std::uint64_t image_base;
                std::uint32_t section_alignment;
                std::uint32_t file_alignment;
                std::uint16_t major_operating_system_version;
                std::uint16_t minor_operating_system_version;
                std::uint16_t major_image_version;
                std::uint16_t minor_image_version;
                std::uint16_t major_subsystem_version;
                std::uint16_t minor_subsystem_version;
                std::uint32_t win32_version_value;
                std::uint32_t size_of_image;
                std::uint32_t size_of_headers;
                std::uint32_t check_sum;
                std::uint16_t subsystem;
                std::uint16_t dll_characteristics;
                std::uint64_t size_of_stack_reserve;
                std::uint64_t size_of_stack_commit;
                std::uint64_t size_of_heap_reserver;
                std::uint64_t size_of_heap_commit;
                std::uint32_t lodaer_flags;
                std::uint32_t number_of_rva_and_sizes;
                union {
                    struct {
                        image_data_directory_t export_directory;       // 0
                        image_data_directory_t import_directory;       // 1
                        image_data_directory_t resource_directory;     // 2
                        image_data_directory_t exception_directory;    // 3
                        image_data_directory_t security_directory;     // 4
                        image_data_directory_t basereloc_directory;    // 5
                        image_data_directory_t debug_directory;        // 6
                        image_data_directory_t architecture_directory; // 7
                        image_data_directory_t globalptr_directory;    // 8
                        image_data_directory_t tls_directory;          // 9
                        image_data_directory_t load_config_directory;  // 10
                        image_data_directory_t bound_import_directory; // 11
                        image_data_directory_t iat_directory;          // 12
                        image_data_directory_t delay_import_directory; // 13
                        image_data_directory_t com_directory;          // 14
                        image_data_directory_t reserved;               // 15
                    };
                    image_data_directory_t data_directory[16];
                };
            };

            struct image_nt_headers {
                std::uint32_t signature;
                image_file_header_t file_header;
                image_optional_header64_t optional_header;
            };

            struct image_export_directory_t {
                std::uint32_t characteristics;
                std::uint32_t time_date_stamp;
                std::uint16_t major_version;
                std::uint16_t minor_version;
                std::uint32_t name;
                std::uint32_t base;
                std::uint32_t number_of_functions;
                std::uint32_t number_of_names;
                std::uint32_t address_of_functions;
                std::uint32_t address_of_names;
                std::uint32_t address_of_name_ordinals;
            };

            struct image_section_header_t {
                std::uint8_t name[8];
                union {
                    std::uint32_t physical_address;
                    std::uint32_t virtual_size;
                } misc;
                std::uint32_t virtual_address;
                std::uint32_t size_of_raw_data;
                std::uint32_t pointer_to_raw_data;
                std::uint32_t pointer_to_relocations;
                std::uint32_t pointer_to_linenumbers;
                std::uint16_t number_of_relocations;
                std::uint16_t number_of_linenumbers;
                std::uint32_t characteristics;
            };
        }

        inline auto wstr_to_str(const std::wstring& data) -> std::string {
            if (data.empty())
                return {};

            const int required_length = WideCharToMultiByte(
                CP_UTF8,
                0,
                &data[0],
                static_cast<int>(data.size()),
                nullptr,
                0,
                nullptr,
                nullptr);

            std::string result = {};
            result.resize(required_length);
            WideCharToMultiByte(
                CP_UTF8,
                0,
                &data[0],
                static_cast<int>(data.size()),
                &result[0],
                required_length,
                nullptr,
                nullptr);

            return result;
        }

        inline auto wstr_to_str(const std::wstring_view data) -> std::string {
            if (data.empty())
                return {};

            const int required_length = WideCharToMultiByte(
                CP_UTF8, // CodePage
                0,       // dwFlags
                &data[0],
                static_cast<int>(data.size()),
                nullptr,
                0,
                nullptr,
                nullptr);

            std::string result = {};
            result.resize(required_length);
            WideCharToMultiByte(
                CP_UTF8,
                0,
                &data[0],
                static_cast<int>(data.size()),
                &result[0],
                required_length,
                nullptr,
                nullptr);

            return result;
        }

        inline auto str_to_wstr(const std::string& data) -> std::wstring {
            if (data.empty())
                return {};

             const int required_length = MultiByteToWideChar(
                CP_UTF8,
                0,
                &data[0],
                static_cast<int>(data.size()),
                nullptr,
                NULL);

            std::wstring result = {};
            result.resize(required_length);
            MultiByteToWideChar(
                CP_UTF8,
                0,
                &data[0],
                static_cast<int>(data.size()),
                &result[0],
                required_length);

            return result;
        }

        inline auto str_to_wstr(const std::string_view data) -> std::wstring {
            if (data.empty())
                return {};

            const int required_length = MultiByteToWideChar(
                CP_UTF8,
                0,
                &data[0],
                static_cast<int>(data.size()),
                nullptr,
                NULL);

            std::wstring result = {};
            result.resize(required_length);
            MultiByteToWideChar(
                CP_UTF8,
                0,
                &data[0],
                static_cast<int>(data.size()),
                &result[0],
                required_length);

            return result;
        }

        struct module_info_t {
            address_t base;
            hash::fnv1a64_t name;
            hash::fnv1a64_t trimmed_nama;
            std::string path;
        };

        namespace view
        {
            class module_view_t {
            public:
                module_view_t() {
                    _head = &get_peb()->ldr->in_load_order_module_list;
                }

                auto skip_module() -> void {
                    _head = _head->flink;
                }

                class iterator {
                public:
                    using iterator_category = std::bidirectional_iterator_tag;
                    using value_type = module_info_t;
                    using difference_type = std::ptrdiff_t;
                    using pointer = value_type*;
                    using reference = value_type&;

                    iterator() = default;

                    iterator(win::list_entry_t* current, win::list_entry_t* head)
                        : _current(current), _head(head) {

                        update();
                    }

                    pointer operator->() const {
                        return &_module_info;
                    }

                    reference operator*() const {
                        return _module_info;
                    }

                    iterator& operator++() {
                        _current = _current->flink;
                        update();
                        return *this;
                    }

                    iterator operator++(int) {
                        iterator& temp = *this;
                        ++(*this);
                        return temp;
                    }

                    iterator& operator--() {
                        _current = _current->blink;
                        update();
                        return *this;
                    }

                    iterator operator--(int) {
                        iterator& temp = *this;
                        --(*this);
                        return temp;
                    }

                    bool operator==(const iterator& other) const {
                        return _current == other._current;
                    }

                    bool operator!=(const iterator& other) const {
                        return _current != other._current;
                    }

                private:
                    mutable module_info_t _module_info;
                    win::list_entry_t* _current = nullptr;
                    win::list_entry_t* _head = nullptr;

                    auto update() -> void {
                        if (_current == _head)
                            return;

                        const win::ldr_data_table_entry_t* table_entry = CONTAINING_RECORD(
                            _current,
                            win::ldr_data_table_entry_t,
                            in_load_order_links);

                        _module_info.base = table_entry->dll_base;

                        if (table_entry->full_dll_name.buffer && table_entry->full_dll_name.length > 0)
                            _module_info.path = wstr_to_str(
                                std::wstring_view(table_entry->full_dll_name.buffer));

                        if (table_entry->base_dll_name.buffer && table_entry->base_dll_name.length > 0) {
                            std::string module_name = wstr_to_str(
                                std::wstring_view(table_entry->base_dll_name.buffer));

                            std::ranges::transform(module_name, module_name.begin(), ::tolower);

                            _module_info.name = hash::fnv1a64(module_name);

                            _module_info.trimmed_nama = hash::fnv1a64(
                                module_name.substr(0, module_name.length() - 4));
                        }
                    }
                };

                [[nodiscard]] iterator begin() const {
                    return {_head->flink, _head};
                }

                [[nodiscard]] iterator end() const {
                    return {_head, _head};
                }

                [[nodiscard]] iterator find(hash::fnv1a64_t module_name) const {
                    return std::ranges::find_if(begin(), end(), [module_name](const module_info_t& m) -> bool {
                        return m.name == module_name;
                    });
                }

                template <typename Predicate>
                [[nodiscard]] iterator find_if(Predicate predicate) const {
                    return std::ranges::find_if(begin(), end(), predicate);
                }

            private:
                win::list_entry_t* _head;

                [[nodiscard]] static auto get_peb() -> win::peb_t* {
                    return reinterpret_cast<win::peb_t*>(__readgsqword(0x60));
                }
            };

            struct export_info_t {
                hash::fnv1a64_t name;
                address_t address;
                std::uint16_t ordinal;
                bool is_forwarded;
            };

            class export_view_t {
            public:
                export_view_t(const address_t& module_base)
                    : _module_base(module_base) {
                }

                [[nodiscard]] auto count() const -> uint32_t {
                    return export_directory()->number_of_names;
                }

                [[nodiscard]] auto function(const std::uint16_t idx) const -> address_t {
                    const win::image_export_directory_t* export_dir = export_directory();
                    const auto function_table = _module_base.offset<std::uint32_t*>(export_dir->address_of_functions);
                    const auto ordinal_table = _module_base.offset<std::uint16_t*>(export_dir->address_of_name_ordinals);

                    return _module_base.offset(function_table[ordinal_table[idx]]);
                }

                [[nodiscard]] auto name(const std::uint16_t idx) const -> hash::fnv1a64_t {
                    const win::image_export_directory_t* export_dir = export_directory();
                    const auto name_table = _module_base.offset<std::uint32_t*>(export_dir->address_of_names);

                    auto export_name = _module_base.offset<const char*>(name_table[idx]);
                    return hash::fnv1a64(std::string_view(export_name));
                }

                [[nodiscard]] auto ordinal(const std::uint16_t idx) const -> std::uint16_t {
                    const win::image_export_directory_t* export_dir = export_directory();
                    const auto ordinal_table = _module_base.offset<std::uint16_t*>(export_dir->address_of_name_ordinals);

                    return ordinal_table[idx];
                }

                [[nodiscard]] auto is_forwarded(const address_t& export_address) const -> bool {
                    const win::image_data_directory_t* export_data_dir = export_data_directory();
                    const address_t export_start = _module_base.offset(export_data_dir->virtual_address);
                    const address_t export_end = export_start.offset(export_data_dir->size);

                    return export_address > export_start && export_address < export_end;
                }

                class iterator {
                public:
                    using iterator_category = std::bidirectional_iterator_tag;
                    using value_type = export_info_t;
                    using difference_type = std::ptrdiff_t;
                    using pointer = const value_type*;
                    using reference = const value_type&;

                    iterator() = default;

                    iterator(const export_view_t* export_view, const std::uint32_t current)
                        : _export_view(export_view), _current(current) {
                        update();
                    }

                    pointer operator->() const {
                        return &_export_info;
                    }

                    reference operator*() const {
                        return _export_info;
                    }

                    iterator& operator++() {
                        if (_current < _export_view->count()) {
                            ++_current;
                            if (_current < _export_view->count())
                                update();
                            else
                                reset();
                        } else {
                            reset();
                        }
                        return *this;
                    }

                    iterator operator++(int) {
                        iterator temp = *this;
                        ++(*this);
                        return temp;
                    }

                    iterator& operator--() {
                        if (_current > 0) {
                            --_current;
                            update();
                        }
                        return *this;
                    }

                    iterator operator--(int) {
                        iterator temp = *this;
                        --(*this);
                        return temp;
                    }

                    bool operator==(const iterator& other) const {
                        return _current == other._current && _export_view == other._export_view;
                    }

                    bool operator!=(const iterator& other) const {
                        return _current != other._current || _export_view != other._export_view;
                    }

                private:
                    mutable export_info_t _export_info{};
                    const export_view_t* _export_view = nullptr;
                    std::uint32_t _current = 0;

                    auto update() -> void {
                        if (!_export_view || _current >= _export_view->count())
                            return;

                        const address_t export_address = _export_view->function(_current);
                        _export_info = {
                            .name = _export_view->name(_current),
                            .address = export_address,
                            .ordinal = _export_view->ordinal(_current),
                            .is_forwarded = _export_view->is_forwarded(export_address)};
                    }

                    auto reset() -> void {
                        _export_info = export_info_t{};
                    }
                };

                [[nodiscard]] iterator begin() const {
                    return {this, 0};
                }

                [[nodiscard]] iterator end() const {
                    return {this, count()};
                }

                [[nodiscard]] iterator find(hash::fnv1a64_t export_name) const {
                    return std::ranges::find_if(begin(), end(), [export_name](const export_info_t& e) -> bool {
                        return e.name == export_name;
                    });
                }

                template <typename Predicate>
                [[nodiscard]] iterator find_if(Predicate predicate) const {
                    return std::ranges::find_if(begin(), end(), predicate);
                }

            private:
                address_t _module_base;

                [[nodiscard]] auto export_directory() const -> win::image_export_directory_t* {
                    const auto dos_header = _module_base.as<win::image_dos_header_t*>();
                    const auto nt_headers = _module_base.offset<win::image_nt_headers*>(dos_header->e_lfanew);
                    const win::image_optional_header64_t* optional_header = &nt_headers->optional_header;

                    return _module_base.offset<win::image_export_directory_t*>(optional_header->export_directory.virtual_address);
                }

                [[nodiscard]] auto export_data_directory() const -> win::image_data_directory_t* {
                    const auto dos_header = _module_base.as<win::image_dos_header_t*>();
                    const auto nt_headers = _module_base.offset<win::image_nt_headers*>(dos_header->e_lfanew);
                    const win::image_optional_header64_t* optional_header = &nt_headers->optional_header;

                    return const_cast<win::image_data_directory_t*>(&optional_header->export_directory);
                }
            };
        }

        struct forwarded_string_t {
            hash::fnv1a64_t dll_name;
            hash::fnv1a64_t proc_name;
            std::uint16_t ordinal;
            bool by_ordinal = false;
        };

        inline auto resolve_forwarded_string(const address_t& export_address) -> forwarded_string_t {
            const std::string_view forward_string = export_address.as<const char*>();

            const std::size_t dot_delimiter = forward_string.find_first_of('.');

            std::string trimmed_dll(forward_string.substr(0, dot_delimiter));
            std::ranges::transform(trimmed_dll, trimmed_dll.begin(), ::tolower);

            if (forward_string[dot_delimiter + 1] == '#') {
                const std::string_view ordinal_str = forward_string.substr(dot_delimiter + 2);

                std::uint16_t ordinal = 0;
                for (char c : ordinal_str) {
                    if (c >= '0' && c <= '9')
                        ordinal = ordinal * 10 + (c - '0');
                    else
                        break;
                }

                return {
                    .dll_name = hash::fnv1a64(trimmed_dll),
                    .proc_name = 0,
                    .ordinal = ordinal,
                    .by_ordinal = true};
            }

            std::string_view proc_name = forward_string.substr(dot_delimiter + 1);
            return {
                .dll_name = hash::fnv1a64(trimmed_dll),
                .proc_name = hash::fnv1a64(proc_name),
                .ordinal = 0};
        }

        inline auto resolve_forwarded_export(const view::module_view_t& module_view, const address_t& forwarded_address) -> address_t {
            forwarded_string_t forwarded_string = resolve_forwarded_string(forwarded_address);
            const auto forward_module = module_view.find_if([&forwarded_string](const module_info_t& m) -> bool {
                return m.trimmed_nama == forwarded_string.dll_name;
            });

            if (forward_module == module_view.end())
                return {};

            const view::export_view_t e_view{forward_module->base};
            if (forwarded_string.by_ordinal) {
                const auto _export = e_view.find_if([&forwarded_string](const view::export_info_t& e) -> bool {
                    return e.ordinal == forwarded_string.ordinal;
                });

                if (_export == e_view.end())
                    return {};

                return _export->address;
            }

            const auto _export = e_view.find(forwarded_string.proc_name);
            if (_export == e_view.end())
                return {};

            return _export->address;
        }

        inline auto find_export_by_name(const hash::fnv1a64_t module_name, const hash::fnv1a64_t export_name) -> address_t {
            view::module_view_t m_view;
            m_view.skip_module();

            const auto module = m_view.find(module_name);
            if (module == m_view.end())
                return {};

            const view::export_view_t e_view{module->base};
            const auto _export = e_view.find(export_name);
            if (_export == e_view.end())
                return {};

            if (_export->is_forwarded)
                return resolve_forwarded_export(m_view, _export->address);

            return _export->address;
        }

        inline auto find_export_by_name(const hash::fnv1a64_t export_name) -> address_t {
            view::module_view_t m_view;
            m_view.skip_module();

            for (const auto& m : m_view) {
                const view::export_view_t e_view{m.base};
                const auto _export = e_view.find(export_name);
                if (_export == e_view.end())
                    continue;

                if (_export->is_forwarded)
                    return resolve_forwarded_export(m_view, _export->address);

                return _export->address;
            }

            return {};
        }

        inline auto find_export_by_ordinal(const hash::fnv1a64_t module_name, const std::uint16_t ordinal) -> address_t {
            view::module_view_t m_view;
            m_view.skip_module();

            const auto module = m_view.find(module_name);
            if (module == m_view.end())
                return {};

            const view::export_view_t e_view{module->base};
            const auto _export = e_view.find_if([&ordinal](const view::export_info_t& e) -> bool {
                return e.ordinal == ordinal;
            });

            if (_export == e_view.end())
                return {};

            if (_export->is_forwarded)
                return resolve_forwarded_export(m_view, _export->address);

            return _export->address;
        }

        template <typename T>
        auto normalize_arg(T arg) {
            if constexpr (std::is_same_v<T, std::nullptr_t>)
                return static_cast<void*>(nullptr);

            else if constexpr (std::is_integral_v<T>) {
                if constexpr (std::is_signed_v<T>)
                    return static_cast<std::intptr_t>(arg);
                else
                    return static_cast<std::uintptr_t>(arg);
            } else
                return arg;
        }
    } // namespace detail

    template <typename Ret = void, typename... Args>
    __declspec(noinline) auto call(detail::hash::fnv1a64_t module_name, detail::hash::fnv1a64_t proc_name, Args... args) -> Ret {
        using namespace detail;

        const address_t proc = find_export_by_name(module_name, proc_name);
        if (!proc) {
            if constexpr (std::is_same_v<Ret, void>)
                return;
            else
                return Ret{};
        }

        using fn_t = Ret (*)(decltype(normalize_arg(std::forward<Args>(args)))...);
        const fn_t fn = proc.as<fn_t>();

        return fn(normalize_arg(std::forward<Args>(args))...);
    }

    template <typename Ret = void, typename... Args>
    __declspec(noinline) auto call(detail::hash::fnv1a64_t proc_name, Args... args) -> Ret {
        using namespace detail;

        const address_t proc = find_export_by_name(proc_name);
        if (!proc) {
            if constexpr (std::is_same_v<Ret, void>)
                return;
            else
                return Ret{};
        }

        using fn_t = Ret (*)(decltype(normalize_arg(std::forward<Args>(args)))...);
        const fn_t fn = proc.as<fn_t>();

        return fn(normalize_arg(std::forward<Args>(args))...);
    }

    template <typename Ret = void, typename... Args>
    __declspec(noinline) auto call(detail::hash::fnv1a64_t module_name, std::uint16_t ordinal, Args... args) -> Ret {
        using namespace detail;

        const address_t proc = find_export_by_ordinal(module_name, ordinal);
        if (!proc) {
            if constexpr (std::is_same_v<Ret, void>)
                return;
            else
                return Ret{};
        }

        using fn_t = Ret (*)(decltype(normalize_arg(std::forward<Args>(args)))...);
        const fn_t fn = proc.as<fn_t>();

        return fn(normalize_arg(std::forward<Args>(args))...);
    }
} // namespace shadow

consteval auto operator""_fnv1a64(const char* literal, const std::size_t length) -> shadow::detail::hash::fnv1a64_t {
    return shadow::detail::hash::fnv1a64(literal, length);
}

#endif // SHADOWCALL_SHADOWCALL_HPP
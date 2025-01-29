# Based on: https://stackoverflow.com/questions/70391510/list-directory-in-jekyll

module Jekyll
  module ListContent
    def get_files(folder, type="*.png")
      files = Dir
        .glob(folder + "**/" + type)
        .select { |e| File.file? e }
    end

    def get_folders(folder)
      folders = Dir
        .glob(folder + '**/*')
        .select { |e| File.directory? e }
    end
  end
end

Liquid::Template.register_filter(Jekyll::ListContent)
